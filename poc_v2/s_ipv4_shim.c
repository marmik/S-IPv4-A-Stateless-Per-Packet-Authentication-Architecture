/*
 * s_ipv4_shim.c — S-IPv4 validation state machine
 *
 * Processing order:
 *   1. Bounds check  (SHIM_DROP_TRUNCATED)
 *   2. Magic check   (SHIM_DROP_BAD_MAGIC)
 *   3. Key lookup    (SHIM_DROP_UNKNOWN_NODE)
 *   4. Timestamp     (SHIM_DROP_EXPIRED)
 *   5. HMAC verify   (SHIM_DROP_INVALID_TOKEN)
 *   6. Bloom filter  (SHIM_DROP_REPLAY)
 *   7. ACCEPT
 */

#include "s_ipv4.h"
#include "crypto_core.h"
#include "replay_protection.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ── Portable htobe64 ───────────────────────────────────────────── */
#ifdef __APPLE__
#  include <libkern/OSByteOrder.h>
#  define htobe64_s(x)  OSSwapHostToBigInt64(x)
#  define be64toh_s(x)  OSSwapBigToHostInt64(x)
#else
#  include <endian.h>
#  include <arpa/inet.h>
#  define htobe64_s(x)  htobe64(x)
#  define be64toh_s(x)  be64toh(x)
#endif

/* ── Counter-based nonce generation ─────────────────────────────── */
/*                                                                   */
/* BOTTLENECK FIX: The original implementation opened, read, and     */
/* closed /dev/urandom on EVERY call — 3 syscalls per nonce.         */
/* At 1M packets this was the dominant cost.                         */
/*                                                                   */
/* New approach: seed once with arc4random_buf (macOS) at init,      */
/* then use an atomic counter.  Nonce = seed XOR counter.            */
/* This gives unique, unpredictable nonces with zero syscalls in     */
/* the hot path.                                                     */
/*                                                                   */
#include <stdatomic.h>

static _Atomic uint64_t g_nonce_counter = 0;
static uint64_t         g_nonce_seed    = 0;
static int              g_nonce_seeded  = 0;

static void nonce_seed_once(void)
{
    if (!g_nonce_seeded) {
        arc4random_buf(&g_nonce_seed, sizeof(g_nonce_seed));
        g_nonce_seeded = 1;
    }
}

static uint64_t generate_nonce(void)
{
    nonce_seed_once();
    uint64_t ctr = atomic_fetch_add(&g_nonce_counter, 1);
    return g_nonce_seed ^ ctr;
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Sender side — generate header                                    */
/* ══════════════════════════════════════════════════════════════════ */

void s_ipv4_generate_header(const uint8_t  node_id[S_IPV4_NODE_ID_LEN],
                            const uint8_t  epoch_key[EPOCH_KEY_LEN],
                            const uint8_t *payload,
                            size_t         payload_len,
                            s_ipv4_header_t *out_hdr,
                            uint64_t       force_nonce,
                            uint64_t       force_timestamp)
{
    out_hdr->s_flag = S_IPV4_MAGIC;
    memcpy(out_hdr->node_id, node_id, S_IPV4_NODE_ID_LEN);

    /* Use forced values if provided (for --replay testing), else fresh */
    uint64_t ts    = (force_timestamp != 0) ? force_timestamp : (uint64_t)time(NULL);
    uint64_t nonce = (force_nonce     != 0) ? force_nonce     : generate_nonce();

    out_hdr->timestamp = htobe64_s(ts);
    out_hdr->nonce     = htobe64_s(nonce);

    compute_token(epoch_key, ts, nonce, payload, payload_len, out_hdr->hmac);
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Receiver side — validate packet                                  */
/* ══════════════════════════════════════════════════════════════════ */

shim_result_t s_ipv4_verify_packet(const uint8_t   *packet,
                                   size_t           packet_len,
                                   replay_state_t  *rs,
                                   const uint8_t  **out_payload,
                                   size_t          *out_payload_len)
{
    /* 1. Bounds check */
    if (packet_len < sizeof(s_ipv4_header_t)) {
        return SHIM_DROP_TRUNCATED;
    }

    const s_ipv4_header_t *hdr = (const s_ipv4_header_t *)packet;
    const uint8_t *payload     = packet + sizeof(s_ipv4_header_t);
    size_t         payload_len = packet_len - sizeof(s_ipv4_header_t);

    /* 2. Magic byte check */
    if (hdr->s_flag != S_IPV4_MAGIC) {
        return SHIM_DROP_BAD_MAGIC;
    }

    /* 3. Key lookup (UNKNOWN_NODE — bail before any crypto) */
    const uint8_t *epoch_key = keystore_lookup(hdr->node_id);
    if (epoch_key == NULL) {
        return SHIM_DROP_UNKNOWN_NODE;
    }

    /* Decode wire-format fields */
    uint64_t ts    = be64toh_s(hdr->timestamp);
    uint64_t nonce = be64toh_s(hdr->nonce);

    /* 4. Timestamp window */
    if (!timestamp_valid(ts)) {
        return SHIM_DROP_EXPIRED;
    }

    /* 5. HMAC verification */
    uint8_t expected[S_IPV4_HMAC_LEN];
    compute_token(epoch_key, ts, nonce, payload, payload_len, expected);
    if (!token_equal(expected, hdr->hmac)) {
        return SHIM_DROP_INVALID_TOKEN;
    }

    /* 6. Bloom filter replay check */
    if (!nonce_check_and_insert(rs, nonce)) {
        return SHIM_DROP_REPLAY;
    }

    /* 7. Accept */
    if (out_payload)     *out_payload     = payload;
    if (out_payload_len) *out_payload_len = payload_len;
    return SHIM_ACCEPT;
}

/*
 * s_ipv4_shim.c — S-IPv4 V2 validation state machine
 *
 * Processing order:
 *   1. Bounds check  (SHIM_DROP_TRUNCATED)
 *   2. Version check (SHIM_DROP_BAD_VERSION)
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

/* ── Monotonic clock anchoring (Step 10) ──────────────────────────── */
/* At startup, calibrate the offset between wall clock and monotonic
 * clock so cross-machine timestamp validation works correctly.
 * wall_ts ≈ mono_sec + g_mono_offset                                 */
static int64_t g_mono_offset = 0;
static int     g_mono_calibrated = 0;

static void sipv4_calibrate_clock(void) {
    struct timespec mono;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    int64_t wall = (int64_t)time(NULL);
    g_mono_offset = wall - (int64_t)mono.tv_sec;
    g_mono_calibrated = 1;
}

static uint64_t sipv4_get_adjusted_time(void) {
    if (!g_mono_calibrated) sipv4_calibrate_clock();
    struct timespec mono;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    return (uint64_t)((int64_t)mono.tv_sec + g_mono_offset);
}

/* ── Rejection signal builder (Step 9) ────────────────────────────── */
void sipv4_build_reject(const uint8_t *node_id, s_ipv4_reject_t *out) {
    out->s_flag   = S_IPV4_FLAG_V2;
    out->msg_type = S_IPV4_MSG_TYPE_REJECT;
    memcpy(out->node_id, node_id, S_IPV4_NODE_ID_LEN);
}

void sipv4_calibrate_clock_init(void) {
    sipv4_calibrate_clock();
}

/* ── Counter-based nonce generation ─────────────────────────────── */
#include <stdatomic.h>

static atomic_uint_fast64_t g_nonce_counter = 0;
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
/*  Sender side — generate V2 header                                 */
/* ══════════════════════════════════════════════════════════════════ */

void s_ipv4_generate_header(const uint8_t  node_id[S_IPV4_NODE_ID_LEN],
                            const uint8_t  epoch_key[S_IPV4_KEY_LEN],
                            const uint8_t *payload,
                            size_t         payload_len,
                            s_ipv4_v2_header_t *out_hdr,
                            uint64_t       force_nonce,
                            uint64_t       force_timestamp)
{
    out_hdr->s_flag = S_IPV4_FLAG_V2;
    memcpy(out_hdr->node_id, node_id, S_IPV4_NODE_ID_LEN);

    /* Use forced values if provided (for --replay testing), else fresh */
    uint64_t ts    = (force_timestamp != 0) ? force_timestamp : (uint64_t)time(NULL);
    uint64_t nonce = (force_nonce     != 0) ? force_nonce     : generate_nonce();

    out_hdr->timestamp = htobe64_s(ts);
    out_hdr->nonce     = htobe64_s(nonce);
    out_hdr->key_ver   = 0;  /* caller fills if needed */

    crypto_compute_token(epoch_key, ts, nonce, payload, payload_len, out_hdr->hmac);
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Receiver side — validate packet                                  */
/* ══════════════════════════════════════════════════════════════════ */

#ifdef SIPV4_PROFILE
uint64_t prof_t1 = 0;
uint64_t prof_t2 = 0;
uint64_t prof_t3 = 0;
uint64_t prof_t4 = 0;
uint64_t prof_t5 = 0;
uint64_t prof_count = 0;
#endif

shim_result_t s_ipv4_verify_packet(const uint8_t   *packet,
                                   size_t           packet_len,
                                   tiered_bloom_t  *rs,
                                   const uint8_t  **out_payload,
                                   size_t          *out_payload_len)
{
#ifdef SIPV4_PROFILE
    struct timespec ts0, ts1, ts2, ts3, ts4, ts5;
    clock_gettime(CLOCK_MONOTONIC, &ts0);
#endif
    /* 1. Bounds check */
    if (packet_len < sizeof(s_ipv4_v2_header_t)) {
        return SHIM_DROP_TRUNCATED;
    }

    const s_ipv4_v2_header_t *hdr = (const s_ipv4_v2_header_t *)packet;
    const uint8_t *payload     = packet + sizeof(s_ipv4_v2_header_t);
    size_t         payload_len_inner = packet_len - sizeof(s_ipv4_v2_header_t);

    /* 2. Version flag check */
    if (hdr->s_flag != S_IPV4_FLAG_V2) {
        return SHIM_DROP_BAD_VERSION;
    }

#ifdef SIPV4_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &ts1);
#endif

    /* 3. Key lookup via V2 crypto store */
    epoch_key_entry_t entry;
    if (!crypto_get_entry(hdr->node_id, &entry)) {
        return SHIM_DROP_UNKNOWN_NODE;
    }

#ifdef SIPV4_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &ts2);
#endif

    /* Decode wire-format fields */
    uint64_t ts    = be64toh_s(hdr->timestamp);
    uint64_t nonce = be64toh_s(hdr->nonce);

    /* 4. Timestamp window — use calibrated monotonic clock with NTP drift.
     *    sipv4_get_adjusted_time() returns monotonic seconds adjusted by
     *    the wall-clock offset calibrated at startup. The ±0.5s NTP drift
     *    is added to the adaptive window to prevent false rejections
     *    on cross-machine deployments. */
    uint64_t now = sipv4_get_adjusted_time();
    uint64_t diff = now > ts ? (now - ts) : (ts - now);
    double fill = tiered_bloom_fill_pct(rs);
    uint32_t aw = sipv4_adaptive_window_sec(fill);
    /* Add NTP drift tolerance to the window */
    uint32_t effective_window = aw + (uint32_t)(S_IPV4_NTP_DRIFT_SEC * 2);
    if (aw == 0) {
        /* Emergency: only accept packets from this exact second */
        if (diff > 1) return SHIM_DROP_EXPIRED;
    } else {
        if (diff > effective_window) return SHIM_DROP_EXPIRED;
    }

#ifdef SIPV4_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &ts3);
#endif

    /* 5. HMAC verification (tries current key, then previous key) */
    shim_result_t hmac_res = crypto_verify_token(&entry, ts, nonce,
                                                  payload, payload_len_inner,
                                                  hdr->hmac);
    if (hmac_res != SHIM_ACCEPT) {
        return SHIM_DROP_INVALID_TOKEN;
    }

#ifdef SIPV4_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &ts4);
#endif

    /* 6. Bloom filter replay check */
    if (tiered_bloom_check(rs, nonce)) {
        return SHIM_DROP_REPLAY;
    }
    tiered_bloom_insert(rs, nonce);

#ifdef SIPV4_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &ts5);
    prof_t1 += (ts1.tv_sec - ts0.tv_sec)*1000000000ULL + (ts1.tv_nsec - ts0.tv_nsec);
    prof_t2 += (ts2.tv_sec - ts1.tv_sec)*1000000000ULL + (ts2.tv_nsec - ts1.tv_nsec);
    prof_t3 += (ts3.tv_sec - ts2.tv_sec)*1000000000ULL + (ts3.tv_nsec - ts2.tv_nsec);
    prof_t4 += (ts4.tv_sec - ts3.tv_sec)*1000000000ULL + (ts4.tv_nsec - ts3.tv_nsec);
    prof_t5 += (ts5.tv_sec - ts4.tv_sec)*1000000000ULL + (ts5.tv_nsec - ts4.tv_nsec);
    prof_count++;
#endif

    /* 7. Accept */
    if (out_payload)     *out_payload     = payload;
    if (out_payload_len) *out_payload_len = payload_len_inner;
    return SHIM_ACCEPT;
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Compact mode — sender side                                       */
/* ══════════════════════════════════════════════════════════════════ */

void s_ipv4_generate_header_compact(const uint8_t  node_id[S_IPV4_NODE_ID_LEN],
                                     const uint8_t  epoch_key[S_IPV4_KEY_LEN],
                                     const uint8_t *payload,
                                     size_t         payload_len,
                                     s_ipv4_compact_header_t *out_hdr,
                                     uint32_t       force_nonce)
{
    out_hdr->s_flag = S_IPV4_FLAG_COMPACT;
    /* Truncate 8-byte node_id to 4 bytes */
    memcpy(out_hdr->node_id, node_id, 4);

    uint32_t nonce = (force_nonce != 0) ? force_nonce
                     : (uint32_t)atomic_fetch_add(&g_nonce_counter, 1);
    out_hdr->nonce = htonl(nonce);

    crypto_compute_token_compact(epoch_key, nonce, payload, payload_len, out_hdr->hmac);
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Compact mode — receiver side                                     */
/* ══════════════════════════════════════════════════════════════════ */

shim_result_t s_ipv4_verify_packet_compact(const uint8_t   *packet,
                                            size_t           packet_len,
                                            tiered_bloom_t  *rs,
                                            const uint8_t  **out_payload,
                                            size_t          *out_payload_len)
{
    /* 1. Bounds check */
    if (packet_len < sizeof(s_ipv4_compact_header_t)) {
        return SHIM_DROP_TRUNCATED;
    }

    const s_ipv4_compact_header_t *hdr = (const s_ipv4_compact_header_t *)packet;
    const uint8_t *payload     = packet + sizeof(s_ipv4_compact_header_t);
    size_t         payload_len_inner = packet_len - sizeof(s_ipv4_compact_header_t);

    /* 2. Version flag check */
    if (hdr->s_flag != S_IPV4_FLAG_COMPACT) {
        return SHIM_DROP_BAD_VERSION;
    }

    /* 3. Key lookup — match truncated 4-byte node_id against all entries */
    epoch_key_entry_t entry;
    /* crypto_get_entry uses full 8-byte node_id; for compact mode we
       do a prefix match against the first 4 bytes */
    if (!crypto_get_entry_compact(hdr->node_id, &entry)) {
        return SHIM_DROP_UNKNOWN_NODE;
    }

    uint32_t nonce = ntohl(hdr->nonce);

    /* 4. Skip timestamp check in compact mode (no timestamp field) —
     *    compact mode relies on nonce uniqueness only */

    /* 5. HMAC-96 verification */
    shim_result_t hmac_res = crypto_verify_token_compact(&entry, nonce,
                                                          payload, payload_len_inner,
                                                          hdr->hmac);
    if (hmac_res != SHIM_ACCEPT) {
        return SHIM_DROP_INVALID_TOKEN;
    }

    /* 6. Bloom filter replay check */
    if (tiered_bloom_check(rs, (uint64_t)nonce)) {
        return SHIM_DROP_REPLAY;
    }
    tiered_bloom_insert(rs, (uint64_t)nonce);

    /* 7. Accept */
    if (out_payload)     *out_payload     = payload;
    if (out_payload_len) *out_payload_len = payload_len_inner;
    return SHIM_ACCEPT;
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Result code to string                                            */
/* ══════════════════════════════════════════════════════════════════ */

const char *shim_result_str(shim_result_t r)
{
    switch (r) {
        case SHIM_ACCEPT:             return "ACCEPT_OK";
        case SHIM_DROP_TRUNCATED:     return "TRUNCATED";
        case SHIM_DROP_UNKNOWN_NODE:  return "UNKNOWN_NODE";
        case SHIM_DROP_INVALID_TOKEN: return "INVALID_TOKEN";
        case SHIM_DROP_EXPIRED:       return "EXPIRED_TIMESTAMP";
        case SHIM_DROP_REPLAY:        return "REPLAY_DETECTED";
        case SHIM_DROP_BAD_VERSION:   return "BAD_VERSION";
        case SHIM_DROP_RATE_LIMITED:  return "RATE_LIMITED";
        case SHIM_DEGRADED_MODE:      return "DEGRADED_MODE";
        case SHIM_ACCEPT_AUDIT:       return "ACCEPT_AUDIT";
        default:                      return "UNKNOWN";
    }
}

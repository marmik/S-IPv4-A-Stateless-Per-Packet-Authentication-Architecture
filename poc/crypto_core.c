/*
 * crypto_core.c — Cryptographic primitives for S-IPv4
 *
 * • Mock key store mapping NodeID → epoch key
 * • HMAC-SHA256 token generation (big-endian serialization)
 * • Constant-time token comparison via CRYPTO_memcmp
 */

#include "crypto_core.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/* ── Portable htobe64 ───────────────────────────────────────────── */
#ifdef __APPLE__
#  include <libkern/OSByteOrder.h>
#  define htobe64_s(x)  OSSwapHostToBigInt64(x)
#else
#  include <endian.h>
#  define htobe64_s(x)  htobe64(x)
#endif

/* ══════════════════════════════════════════════════════════════════ */
/*  Key Store (simple in-memory mock — replace with real DB/HSM)    */
/* ══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t node_id[S_IPV4_NODE_ID_LEN];
    uint8_t epoch_key[EPOCH_KEY_LEN];
    int     active;
} keystore_entry_t;

static keystore_entry_t g_keystore[MAX_NODES];
static int              g_keystore_count = 0;

int keystore_register(const uint8_t node_id[S_IPV4_NODE_ID_LEN],
                      const uint8_t epoch_key[EPOCH_KEY_LEN])
{
    if (g_keystore_count >= MAX_NODES) return -1;
    keystore_entry_t *e = &g_keystore[g_keystore_count++];
    memcpy(e->node_id,  node_id,  S_IPV4_NODE_ID_LEN);
    memcpy(e->epoch_key, epoch_key, EPOCH_KEY_LEN);
    e->active = 1;
    return 0;
}

const uint8_t *keystore_lookup(const uint8_t node_id[S_IPV4_NODE_ID_LEN])
{
    for (int i = 0; i < g_keystore_count; i++) {
        if (g_keystore[i].active &&
            memcmp(g_keystore[i].node_id, node_id, S_IPV4_NODE_ID_LEN) == 0)
        {
            return g_keystore[i].epoch_key;
        }
    }
    return NULL;   /* UNKNOWN_NODE — caller must handle */
}

/* ══════════════════════════════════════════════════════════════════ */
/*  HMAC Token                                                       */
/* ══════════════════════════════════════════════════════════════════ */

/*
 * HMAC input message (all big-endian):
 *   [ timestamp  8 bytes ]
 *   [ nonce      8 bytes ]
 *   [ SHA-256(payload) 32 bytes ]
 *
 * Output: first S_IPV4_HMAC_LEN bytes of HMAC-SHA-256.
 *
 * BOTTLENECK FIX: OpenSSL's HMAC() convenience function allocates
 * and frees an HMAC_CTX on every call. Use a static pre-allocated
 * context to eliminate per-packet heap allocations.
 * We also do this for SHA256() to avoid OpenSSL 3 provider allocations.
 */
void compute_token(const uint8_t epoch_key[EPOCH_KEY_LEN],
                   uint64_t       timestamp,
                   uint64_t       nonce,
                   const uint8_t *payload,
                   size_t         payload_len,
                   uint8_t        out_hmac[S_IPV4_HMAC_LEN])
{
    /* 1. Hash the payload first using pre-allocated context */
    static _Thread_local EVP_MD_CTX *md_ctx = NULL;
    static _Thread_local int md_ctx_init = 0;
    if (!md_ctx) {
        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) { perror("EVP_MD_CTX_new"); exit(1); }
    }

    uint8_t payload_hash[SHA256_DIGEST_LENGTH];
    unsigned int md_len = 0;
    if (!md_ctx_init) {
        EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
        md_ctx_init = 1;
    } else {
        EVP_DigestInit_ex(md_ctx, NULL, NULL); /* reuse provider */
    }
    EVP_DigestUpdate(md_ctx, payload, payload_len);
    EVP_DigestFinal_ex(md_ctx, payload_hash, &md_len);

    /* 2. Build the HMAC input message — all fields big-endian */
    uint8_t msg[8 + 8 + SHA256_DIGEST_LENGTH];
    uint64_t ts_be = htobe64_s(timestamp);
    uint64_t nc_be = htobe64_s(nonce);
    memcpy(msg,      &ts_be,       8);
    memcpy(msg + 8,  &nc_be,       8);
    memcpy(msg + 16, payload_hash, SHA256_DIGEST_LENGTH);

    /* 3. Compute HMAC-SHA-256 using pre-allocated context */
    static _Thread_local HMAC_CTX *hmac_ctx = NULL;
    static _Thread_local const uint8_t *last_key = NULL;
    if (!hmac_ctx) {
        hmac_ctx = HMAC_CTX_new();
        if (!hmac_ctx) { perror("HMAC_CTX_new"); exit(1); }
    }

    uint8_t  full_hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    if (epoch_key != last_key) {
        HMAC_Init_ex(hmac_ctx, epoch_key, EPOCH_KEY_LEN, EVP_sha256(), NULL);
        last_key = epoch_key;
    } else {
        HMAC_Init_ex(hmac_ctx, NULL, 0, NULL, NULL); /* reuse key & provider */
    }
    HMAC_Update(hmac_ctx, msg, sizeof(msg));
    HMAC_Final(hmac_ctx, full_hmac, &hmac_len);

    /* 4. Truncate to S_IPV4_HMAC_LEN */
    memcpy(out_hmac, full_hmac, S_IPV4_HMAC_LEN);
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Constant-time comparison                                         */
/* ══════════════════════════════════════════════════════════════════ */

bool token_equal(const uint8_t a[S_IPV4_HMAC_LEN],
                 const uint8_t b[S_IPV4_HMAC_LEN])
{
    return CRYPTO_memcmp(a, b, S_IPV4_HMAC_LEN) == 0;
}

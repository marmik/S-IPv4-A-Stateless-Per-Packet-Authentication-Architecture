#include "crypto_core.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <string.h>
#include <stdio.h>

#if defined(__APPLE__)
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#else
#include <endian.h>
#endif

/* Thread-local contexts for token generation cache */
static _Thread_local EVP_MAC *t_mac = NULL;
static _Thread_local EVP_MD_CTX *t_md_ctx = NULL;
static _Thread_local EVP_MD *t_sha256_md = NULL;
static _Thread_local EVP_MAC_CTX *t_mac_ctx = NULL;

static epoch_key_entry_t global_entry;

void sipv4_derive_node_id(const uint8_t *epoch_key, uint8_t *node_id_out) {
    uint8_t md[32];
    size_t out_len = 32;

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_END
    };
    EVP_MAC_init(ctx, epoch_key, S_IPV4_KEY_LEN, params);
    EVP_MAC_update(ctx, (const unsigned char *)"node_id_v2", 10);
    EVP_MAC_final(ctx, md, &out_len, 32);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    memcpy(node_id_out, md, S_IPV4_NODE_ID_LEN);
}

void sipv4_hkdf_derive_epoch_key(const uint8_t *master_secret, uint32_t epoch_counter, uint8_t *key_out) {
    uint8_t md[32];
    size_t out_len = 32;
    uint32_t ec_be = htobe32(epoch_counter);
    
    uint8_t input[9];
    memcpy(input, "epoch", 5);
    memcpy(input + 5, &ec_be, 4);

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_END
    };
    EVP_MAC_init(ctx, master_secret, S_IPV4_KEY_LEN, params);
    EVP_MAC_update(ctx, input, 9);
    EVP_MAC_final(ctx, md, &out_len, 32);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    memcpy(key_out, md, S_IPV4_KEY_LEN);
}

void crypto_init(const uint8_t *master_secret) {
    memset(&global_entry, 0, sizeof(global_entry));
    sipv4_hkdf_derive_epoch_key(master_secret, 1, global_entry.current_key);
    global_entry.key_ver = 1;
    global_entry.has_previous = 0;
    sipv4_derive_node_id(global_entry.current_key, global_entry.node_id);
    
    uint64_t node_id_val = 0;
    memcpy(&node_id_val, global_entry.node_id, 8);
    fprintf(stderr, "[S-IPv4 V2] NodeID: %016llX key_ver: %u\n", (unsigned long long)be64toh(node_id_val), global_entry.key_ver);
}

void crypto_rotate_epoch(void) {
    memcpy(global_entry.previous_key, global_entry.current_key, S_IPV4_KEY_LEN);
    global_entry.has_previous = 1;
    global_entry.key_ver++;
    
    uint8_t dummy_master[S_IPV4_KEY_LEN];
    memset(dummy_master, 0xAA, S_IPV4_KEY_LEN); 
    sipv4_hkdf_derive_epoch_key(dummy_master, global_entry.key_ver, global_entry.current_key);
    sipv4_derive_node_id(global_entry.current_key, global_entry.node_id);
}

int crypto_get_entry(const uint8_t *node_id, epoch_key_entry_t *out) {
    if (CRYPTO_memcmp(node_id, global_entry.node_id, S_IPV4_NODE_ID_LEN) == 0) {
        *out = global_entry;
        return 1;
    }
    return 0;
}

int crypto_get_entry_compact(const uint8_t *node_id_4, epoch_key_entry_t *out) {
    /* Compact mode uses first 4 bytes of the full 8-byte node_id */
    if (CRYPTO_memcmp(node_id_4, global_entry.node_id, 4) == 0) {
        *out = global_entry;
        return 1;
    }
    return 0;
}

void crypto_compute_token(const uint8_t *epoch_key, uint64_t timestamp, uint64_t nonce, const uint8_t *payload, size_t payload_len, uint8_t *token_out) {
    if (!t_mac) {
        t_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    }
    if (!t_md_ctx) {
        t_md_ctx = EVP_MD_CTX_new();
    }
    if (!t_sha256_md) {
        t_sha256_md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    }
    if (!t_mac_ctx) {
        t_mac_ctx = EVP_MAC_CTX_new(t_mac);
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
            OSSL_PARAM_END
        };
        EVP_MAC_init(t_mac_ctx, NULL, 0, params);
    }
    
    uint8_t payload_hash[32];
    unsigned int md_len;
    EVP_DigestInit_ex(t_md_ctx, t_sha256_md, NULL);
    EVP_DigestUpdate(t_md_ctx, payload, payload_len);
    EVP_DigestFinal_ex(t_md_ctx, payload_hash, &md_len);

    uint64_t ts_be = htobe64(timestamp);
    uint64_t n_be = htobe64(nonce);

    EVP_MAC_init(t_mac_ctx, epoch_key, S_IPV4_KEY_LEN, NULL);
    EVP_MAC_update(t_mac_ctx, payload_hash, 32);
    EVP_MAC_update(t_mac_ctx, (const unsigned char *)&ts_be, 8);
    EVP_MAC_update(t_mac_ctx, (const unsigned char *)&n_be, 8);
    
    uint8_t full_mac[32];
    size_t out_len = 32;
    EVP_MAC_final(t_mac_ctx, full_mac, &out_len, 32);

    memcpy(token_out, full_mac, 16);
}

shim_result_t crypto_verify_token(const epoch_key_entry_t *entry, uint64_t timestamp, uint64_t nonce, const uint8_t *payload, size_t payload_len, const uint8_t *token_in) {
    uint8_t computed[16];
    crypto_compute_token(entry->current_key, timestamp, nonce, payload, payload_len, computed);
    
    if (CRYPTO_memcmp(computed, token_in, 16) == 0) {
        return SHIM_ACCEPT;
    }
    
    if (entry->has_previous) {
        crypto_compute_token(entry->previous_key, timestamp, nonce, payload, payload_len, computed);
        if (CRYPTO_memcmp(computed, token_in, 16) == 0) {
            return SHIM_ACCEPT;
        }
    }
    
    return SHIM_DROP_INVALID_TOKEN;
}

/* ── Compact mode (HMAC-96) ─────────────────────────────────────── */

void crypto_compute_token_compact(const uint8_t *epoch_key,
                                   uint32_t nonce,
                                   const uint8_t *payload, size_t payload_len,
                                   uint8_t *token_out_12)
{
    if (!t_mac) {
        t_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    }
    if (!t_md_ctx) {
        t_md_ctx = EVP_MD_CTX_new();
    }
    if (!t_sha256_md) {
        t_sha256_md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    }
    if (!t_mac_ctx) {
        t_mac_ctx = EVP_MAC_CTX_new(t_mac);
        /* Initialize with params ONCE */
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
            OSSL_PARAM_END
        };
        EVP_MAC_init(t_mac_ctx, NULL, 0, params);
    }

    /* Hash payload first (same pattern as full mode) */
    uint8_t payload_hash[32];
    unsigned int md_len;
    EVP_DigestInit_ex(t_md_ctx, t_sha256_md, NULL);
    EVP_DigestUpdate(t_md_ctx, payload, payload_len);
    EVP_DigestFinal_ex(t_md_ctx, payload_hash, &md_len);

    uint32_t n_be = htobe32(nonce);

    EVP_MAC_init(t_mac_ctx, epoch_key, S_IPV4_KEY_LEN, NULL);
    EVP_MAC_update(t_mac_ctx, payload_hash, 32);
    EVP_MAC_update(t_mac_ctx, (const unsigned char *)&n_be, 4);

    uint8_t full_mac[32];
    size_t out_len = 32;
    EVP_MAC_final(t_mac_ctx, full_mac, &out_len, 32);

    /* Truncate to 12 bytes (HMAC-96 per RFC 2404) */
    memcpy(token_out_12, full_mac, 12);
}

shim_result_t crypto_verify_token_compact(const epoch_key_entry_t *entry,
                                           uint32_t nonce,
                                           const uint8_t *payload, size_t payload_len,
                                           const uint8_t *token_in_12)
{
    uint8_t computed[12];
    crypto_compute_token_compact(entry->current_key, nonce, payload, payload_len, computed);

    if (CRYPTO_memcmp(computed, token_in_12, 12) == 0) {
        return SHIM_ACCEPT;
    }

    if (entry->has_previous) {
        crypto_compute_token_compact(entry->previous_key, nonce, payload, payload_len, computed);
        if (CRYPTO_memcmp(computed, token_in_12, 12) == 0) {
            return SHIM_ACCEPT;
        }
    }

    return SHIM_DROP_INVALID_TOKEN;
}

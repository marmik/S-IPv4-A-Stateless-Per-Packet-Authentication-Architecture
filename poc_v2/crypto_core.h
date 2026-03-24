#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H

#include "s_ipv4.h"
#include <stdint.h>

/* ── Epoch Key store entry ───────────────────────────────────────── */
typedef struct {
    uint8_t  node_id[S_IPV4_NODE_ID_LEN];
    uint8_t  current_key[S_IPV4_KEY_LEN];
    uint8_t  previous_key[S_IPV4_KEY_LEN];
    uint16_t key_ver;           /* current epoch version counter      */
    int      has_previous;      /* 1 if previous key is valid         */
} epoch_key_entry_t;

/* ── Key derivation ─────────────────────────────────────────────── */
void sipv4_derive_node_id(const uint8_t *epoch_key, uint8_t *node_id_out);
void sipv4_hkdf_derive_epoch_key(const uint8_t *master_secret,
                                  uint32_t epoch_counter,
                                  uint8_t *key_out);

/* ── Key store operations ───────────────────────────────────────── */
void   crypto_init(const uint8_t *master_secret);
void   crypto_rotate_epoch(void);
int    crypto_get_entry(const uint8_t *node_id, epoch_key_entry_t *out);

/* ── Token operations ───────────────────────────────────────────── */
void   crypto_compute_token(const uint8_t *epoch_key,
                             uint64_t timestamp, uint64_t nonce,
                             const uint8_t *payload, size_t payload_len,
                             uint8_t *token_out);

shim_result_t crypto_verify_token(const epoch_key_entry_t *entry,
                                   uint64_t timestamp, uint64_t nonce,
                                   const uint8_t *payload, size_t payload_len,
                                   const uint8_t *token_in);

#endif /* CRYPTO_CORE_H */

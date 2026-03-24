/*
 * crypto_core.h — Cryptographic primitives for S-IPv4
 */

#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H

#include "s_ipv4.h"
#include <stdbool.h>

/* ── Key Store ──────────────────────────────────────────────────── */
/* Maximum number of registered nodes in the mock key store.        */
#define MAX_NODES  16

/* Length of an epoch key in bytes (256 bits). */
#define EPOCH_KEY_LEN  32

/* Registers a NodeID → epoch key binding.  Returns 0 on success.   */
int  keystore_register(const uint8_t node_id[S_IPV4_NODE_ID_LEN],
                       const uint8_t epoch_key[EPOCH_KEY_LEN]);

/* Looks up the epoch key for a given NodeID.                       */
/* Returns pointer to key on success, NULL if NodeID is unknown.    */
const uint8_t *keystore_lookup(const uint8_t node_id[S_IPV4_NODE_ID_LEN]);

/* ── HMAC Token ─────────────────────────────────────────────────── */
/* Computes the S-IPv4 HMAC token:                                  */
/*   HMAC-SHA256(epoch_key, timestamp_BE || nonce_BE || payload_hash)*/
/* All multi-byte fields serialized in network byte order (BE)      */
/* via htobe64.  Output truncated to S_IPV4_HMAC_LEN bytes.         */
void compute_token(const uint8_t epoch_key[EPOCH_KEY_LEN],
                   uint64_t       timestamp,
                   uint64_t       nonce,
                   const uint8_t *payload,
                   size_t         payload_len,
                   uint8_t        out_hmac[S_IPV4_HMAC_LEN]);

/* Constant-time comparison of two HMAC tokens.                     */
/* Returns true if they are equal.                                  */
bool token_equal(const uint8_t a[S_IPV4_HMAC_LEN],
                 const uint8_t b[S_IPV4_HMAC_LEN]);

#endif /* CRYPTO_CORE_H */

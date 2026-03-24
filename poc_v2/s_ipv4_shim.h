/*
 * s_ipv4_shim.h — S-IPv4 shim layer function declarations
 */

#ifndef S_IPV4_SHIM_H
#define S_IPV4_SHIM_H

#include "s_ipv4.h"
#include "crypto_core.h"
#include "replay_protection.h"

/* Sender: generate an S-IPv4 header for a payload.                 */
/* Set force_nonce / force_timestamp to 0 for fresh random values.  */
void s_ipv4_generate_header(const uint8_t  node_id[S_IPV4_NODE_ID_LEN],
                            const uint8_t  epoch_key[S_IPV4_KEY_LEN],
                            const uint8_t *payload,
                            size_t         payload_len,
                            s_ipv4_v2_header_t *out_hdr,
                            uint64_t       force_nonce,
                            uint64_t       force_timestamp);

/* Receiver: validate a raw packet through the full state machine.  */
shim_result_t s_ipv4_verify_packet(const uint8_t   *packet,
                                   size_t           packet_len,
                                   tiered_bloom_t  *rs,
                                   const uint8_t  **out_payload,
                                   size_t          *out_payload_len);

/* ── Compact mode (21-byte header, 0x96) ─────────────────────────── */
/* Sender: generate compact header for constrained environments.     */
void s_ipv4_generate_header_compact(const uint8_t  node_id[S_IPV4_NODE_ID_LEN],
                                     const uint8_t  epoch_key[S_IPV4_KEY_LEN],
                                     const uint8_t *payload,
                                     size_t         payload_len,
                                     s_ipv4_compact_header_t *out_hdr,
                                     uint32_t       force_nonce);

/* Receiver: validate a compact-mode packet.                         */
shim_result_t s_ipv4_verify_packet_compact(const uint8_t   *packet,
                                            size_t           packet_len,
                                            tiered_bloom_t  *rs,
                                            const uint8_t  **out_payload,
                                            size_t          *out_payload_len);

/* Result code to human-readable string.                             */
const char *shim_result_str(shim_result_t r);

/* ── Rejection signal (Step 9) ───────────────────────────────────── */
void sipv4_build_reject(const uint8_t *node_id, s_ipv4_reject_t *out);

/* ── Clock calibration (Step 10) ─────────────────────────────────── */
void sipv4_calibrate_clock_init(void);

#endif /* S_IPV4_SHIM_H */

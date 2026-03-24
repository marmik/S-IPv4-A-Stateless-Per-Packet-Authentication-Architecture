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
                            const uint8_t  epoch_key[EPOCH_KEY_LEN],
                            const uint8_t *payload,
                            size_t         payload_len,
                            s_ipv4_header_t *out_hdr,
                            uint64_t       force_nonce,
                            uint64_t       force_timestamp);

/* Receiver: validate a raw packet through the full state machine.  */
shim_result_t s_ipv4_verify_packet(const uint8_t   *packet,
                                   size_t           packet_len,
                                   replay_state_t  *rs,
                                   const uint8_t  **out_payload,
                                   size_t          *out_payload_len);

#endif /* S_IPV4_SHIM_H */

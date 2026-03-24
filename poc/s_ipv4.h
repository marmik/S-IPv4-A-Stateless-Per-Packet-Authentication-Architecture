/*
 * s_ipv4.h — S-IPv4 Protocol Header Definitions
 *
 * Stateless Per-Packet Network-Layer Trust Architecture
 * Proof of Concept Implementation
 */

#ifndef S_IPV4_H
#define S_IPV4_H

#include <stdint.h>
#include <stddef.h>

/* ── Magic Byte ─────────────────────────────────────────────────── */
/* First byte of every S-IPv4 mini header.  Allows fast rejection   */
/* of non-S-IPv4 traffic before any crypto work is performed.       */
#define S_IPV4_MAGIC  0x94

/* ── HMAC / Nonce sizes ─────────────────────────────────────────── */
#define S_IPV4_HMAC_LEN   16   /* truncated HMAC-SHA-256 (128 bit) */
#define S_IPV4_NODE_ID_LEN 8   /* 8-byte NodeID                    */

/* ── Timestamp window (seconds) ─────────────────────────────────── */
#define S_IPV4_DELTA_SEC  30   /* ±30 s acceptance window           */

/* ── S-IPv4 Mini Header (wire format) ───────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  s_flag;                        /* must equal S_IPV4_MAGIC   */
    uint8_t  node_id[S_IPV4_NODE_ID_LEN];   /* sender NodeID            */
    uint64_t timestamp;                      /* coarse UTC epoch (BE)    */
    uint64_t nonce;                          /* 64-bit random nonce (BE) */
    uint8_t  hmac[S_IPV4_HMAC_LEN];          /* truncated HMAC token     */
} s_ipv4_header_t;

/* Compile-time size assertion: 1 + 8 + 8 + 8 + 16 = 41 bytes */
_Static_assert(sizeof(s_ipv4_header_t) == 41,
               "s_ipv4_header_t must be exactly 41 bytes on the wire");

/* ── Shim result codes ──────────────────────────────────────────── */
typedef enum {
    SHIM_ACCEPT            =  0,
    SHIM_DROP_TRUNCATED    = -1,
    SHIM_DROP_BAD_MAGIC    = -2,
    SHIM_DROP_UNKNOWN_NODE = -3,
    SHIM_DROP_INVALID_TOKEN= -4,
    SHIM_DROP_EXPIRED      = -5,
    SHIM_DROP_REPLAY       = -6
} shim_result_t;

/* Human-readable reason string for logging */
static inline const char *shim_result_str(shim_result_t r) {
    switch (r) {
        case SHIM_ACCEPT:             return "ACCEPT";
        case SHIM_DROP_TRUNCATED:     return "TRUNCATED";
        case SHIM_DROP_BAD_MAGIC:     return "BAD_MAGIC";
        case SHIM_DROP_UNKNOWN_NODE:  return "UNKNOWN_NODE";
        case SHIM_DROP_INVALID_TOKEN: return "INVALID_TOKEN";
        case SHIM_DROP_EXPIRED:       return "EXPIRED_TIMESTAMP";
        case SHIM_DROP_REPLAY:        return "REPLAY_DETECTED";
        default:                      return "UNKNOWN";
    }
}

/* ── Server operating modes ─────────────────────────────────────── */
typedef enum {
    MODE_ENFORCE = 0,   /* drop invalid packets silently          */
    MODE_AUDIT   = 1    /* log but still deliver invalid payloads */
} server_mode_t;

#endif /* S_IPV4_H */


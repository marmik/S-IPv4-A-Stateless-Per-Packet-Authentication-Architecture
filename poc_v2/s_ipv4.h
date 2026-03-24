#ifndef S_IPV4_H
#define S_IPV4_H

#include <stdint.h>
#include <stddef.h>

/* ── Version identifiers ─────────────────────────────────────────── */
#define S_IPV4_VERSION_STR        "2.0"
#define S_IPV4_FLAG_V1            0x94   /* V1 legacy magic byte */
#define S_IPV4_FLAG_V2            0x95   /* V2 full header mode  */
#define S_IPV4_FLAG_COMPACT       0x96   /* V2 compact mode      */
#define S_IPV4_MAGIC_MASK         0xF0   /* upper nibble = 0x90  */
#define S_IPV4_MAGIC_VALUE        0x90
#define S_IPV4_NODE_ID_LEN        8

/* ── Header sizes ────────────────────────────────────────────────── */
#define S_IPV4_V1_HEADER_SIZE     41
#define S_IPV4_V2_HEADER_SIZE     43
#define S_IPV4_COMPACT_HEADER_SIZE 21
#define S_IPV4_MAX_PAYLOAD        1431   /* 1500-20(IP)-8(UDP)-43(S-IPv4) */
#define S_IPV4_COMPACT_MAX_PAYLOAD 1451  /* 1500-20(IP)-8(UDP)-21(compact)*/

/* ── Rejection signal ────────────────────────────────────────────── */
#define S_IPV4_MSG_TYPE_DATA      0x01
#define S_IPV4_MSG_TYPE_REJECT    0x02
#define S_IPV4_REJECT_SIZE        10     /* 1(flag)+1(msg_type)+8(node_id)*/

/* ── Clock drift constants ───────────────────────────────────────── */
#define S_IPV4_NTP_DRIFT_SEC      0.5    /* max assumed NTP drift ±0.5s */

/* ── Epoch Key constants ─────────────────────────────────────────── */
#define S_IPV4_KEY_LEN            32     /* 256-bit HMAC-SHA256 key      */
#define S_IPV4_EPOCH_DURATION_SEC 86400  /* 24-hour default epoch        */
#define S_IPV4_OVERLAP_SEC        60     /* key rotation grace window    */

/* ── V2 packed header struct (43 bytes) ─────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  s_flag;                     /*  1 byte  — versioned magic   */
    uint8_t  node_id[S_IPV4_NODE_ID_LEN];/*  8 bytes — derived identity  */
    uint64_t timestamp;                  /*  8 bytes — big-endian epoch  */
    uint64_t nonce;                      /*  8 bytes — atomic counter    */
    uint16_t key_ver;                    /*  2 bytes — epoch key version */
    uint8_t  hmac[16];                   /* 16 bytes — truncated HMAC    */
} s_ipv4_v2_header_t;                   /* Total: 43 bytes              */

/* ── V2 compact header struct (21 bytes) ────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  s_flag;                     /*  1 byte  — 0x96 magic       */
    uint8_t  node_id[4];                 /*  4 bytes — truncated ID     */
    uint32_t nonce;                      /*  4 bytes — 32-bit counter   */
    uint8_t  hmac[12];                   /* 12 bytes — HMAC-96 (RFC2404)*/
} s_ipv4_compact_header_t;              /* Total: 21 bytes              */

/* ── Rejection signal struct (10 bytes) ──────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  s_flag;                     /*  1 byte  — 0x95 or 0x96     */
    uint8_t  msg_type;                   /*  1 byte  — 0x02 = REJECT    */
    uint8_t  node_id[S_IPV4_NODE_ID_LEN];/*  8 bytes — target node      */
} s_ipv4_reject_t;                      /* Total: 10 bytes              */

/* ── Result codes (V1 + V2 extended) ────────────────────────────── */
typedef enum {
    SHIM_ACCEPT            = 0,
    SHIM_DROP_TRUNCATED    = 1,
    SHIM_DROP_UNKNOWN_NODE = 2,
    SHIM_DROP_INVALID_TOKEN= 3,
    SHIM_DROP_EXPIRED      = 4,
    SHIM_DROP_REPLAY       = 5,
    SHIM_DROP_BAD_VERSION  = 6,
    SHIM_DROP_RATE_LIMITED = 7,
    SHIM_DEGRADED_MODE     = 8,
    SHIM_ACCEPT_AUDIT      = 9
} shim_result_t;

const char *shim_result_str(shim_result_t r);

#endif /* S_IPV4_H */

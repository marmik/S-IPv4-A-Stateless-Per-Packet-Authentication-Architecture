/*
 * client.c — S-IPv4 PoC Client
 *
 * Usage:
 *   ./client <host> <port> <message>
 *   ./client <host> <port> <message> --replay <nonce_hex> <timestamp>
 *   ./client <host> <port> <message> --bad-hmac
 *   ./client <host> <port> <message> --spoof-node
 *   ./client <host> <port> --truncated
 *
 * In normal mode, generates a fresh S-IPv4 header and sends the packet.
 * Prints SENT | Nonce: 0x... | Timestamp: ... so test scripts can
 * capture and replay.
 */

#include "s_ipv4_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <inttypes.h>

/* ── Portable htobe64 ───────────────────────────────────────────── */
#ifdef __APPLE__
#  include <libkern/OSByteOrder.h>
#  define be64toh_s(x)  OSSwapBigToHostInt64(x)
#else
#  include <endian.h>
#  define be64toh_s(x)  be64toh(x)
#endif

/* ── Demo key material (must match server) ──────────────────────── */
static const uint8_t DEMO_NODE_ID[S_IPV4_NODE_ID_LEN] =
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

/* "Other" node for spoofing tests — same NodeID but different key  */
static const uint8_t SPOOF_NODE_ID[S_IPV4_NODE_ID_LEN] =
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};

static const uint8_t DEMO_EPOCH_KEY[EPOCH_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

/* Different key — used with SPOOF_NODE_ID or to produce wrong HMAC */
static const uint8_t WRONG_EPOCH_KEY[EPOCH_KEY_LEN] = {
    0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8,
    0xF7,0xF6,0xF5,0xF4,0xF3,0xF2,0xF1,0xF0,
    0xEF,0xEE,0xED,0xEC,0xEB,0xEA,0xE9,0xE8,
    0xE7,0xE6,0xE5,0xE4,0xE3,0xE2,0xE1,0xE0
};

static void die(const char *msg) { perror(msg); exit(1); }

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <host> <port> <msg>\n"
            "  %s <host> <port> <msg> --replay <nonce_hex> <timestamp>\n"
            "  %s <host> <port> <msg> --bad-hmac\n"
            "  %s <host> <port> <msg> --spoof-node\n"
            "  %s <host> <port> --truncated\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *host = argv[1];
    int port         = atoi(argv[2]);

    /* ── Create UDP socket ─────────────────────────────────────── */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) die("socket");

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    inet_pton(AF_INET, host, &dst.sin_addr);

    /* ── Special case: --truncated ─────────────────────────────── */
    if (argc >= 4 && strcmp(argv[3], "--truncated") == 0) {
        uint8_t tiny[] = {S_IPV4_MAGIC, 0x01, 0x02};  /* 3 bytes < 41 */
        sendto(sock, tiny, sizeof(tiny), 0,
               (struct sockaddr *)&dst, sizeof(dst));
        printf("SENT | TRUNCATED_PACKET | %zu bytes\n", sizeof(tiny));
        close(sock);
        return 0;
    }

    const char   *msg     = argv[3];
    size_t        msg_len = strlen(msg);
    uint64_t      force_nonce = 0;
    uint64_t      force_ts    = 0;
    int           bad_hmac    = 0;
    int           spoof_node  = 0;

    /* ── Parse optional flags ──────────────────────────────────── */
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--replay") == 0 && i + 2 < argc) {
            force_nonce = strtoull(argv[i+1], NULL, 16);
            force_ts    = strtoull(argv[i+2], NULL, 10);
            i += 2;
        } else if (strcmp(argv[i], "--bad-hmac") == 0) {
            bad_hmac = 1;
        } else if (strcmp(argv[i], "--spoof-node") == 0) {
            spoof_node = 1;
        }
    }

    /* ── Build header ──────────────────────────────────────────── */
    s_ipv4_header_t hdr;

    if (spoof_node) {
        /* Use DEMO_NODE_ID but sign with WRONG key → server has  */
        /* DEMO_NODE_ID registered with DEMO key → token mismatch */
        s_ipv4_generate_header(DEMO_NODE_ID, WRONG_EPOCH_KEY,
                               (const uint8_t *)msg, msg_len,
                               &hdr, force_nonce, force_ts);
    } else {
        s_ipv4_generate_header(DEMO_NODE_ID, DEMO_EPOCH_KEY,
                               (const uint8_t *)msg, msg_len,
                               &hdr, force_nonce, force_ts);
    }

    if (bad_hmac) {
        /* Corrupt the last byte of the HMAC */
        hdr.hmac[S_IPV4_HMAC_LEN - 1] ^= 0xFF;
    }

    /* ── Print sent metadata for test script ───────────────────── */
    uint64_t sent_nonce = be64toh_s(hdr.nonce);
    uint64_t sent_ts    = be64toh_s(hdr.timestamp);
    printf("SENT | Nonce: 0x%016" PRIX64 " | Timestamp: %" PRIu64 "\n",
           sent_nonce, sent_ts);

    /* ── Assemble and send packet ──────────────────────────────── */
    size_t pkt_len = sizeof(s_ipv4_header_t) + msg_len;
    uint8_t *pkt   = malloc(pkt_len);
    if (!pkt) die("malloc");

    memcpy(pkt,                      &hdr, sizeof(s_ipv4_header_t));
    memcpy(pkt + sizeof(s_ipv4_header_t), msg, msg_len);

    ssize_t sent = sendto(sock, pkt, pkt_len, 0,
                          (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0) die("sendto");

    printf("SENT | Bytes: %zd | Payload: \"%s\"\n", sent, msg);

    free(pkt);
    close(sock);
    return 0;
}

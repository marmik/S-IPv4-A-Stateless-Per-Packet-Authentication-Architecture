/*
 * server.c — S-IPv4 PoC Server
 *
 * Usage:
 *   ./server <port> ENFORCE     — drop invalid packets
 *   ./server <port> AUDIT       — log but deliver all packets
 *
 * Structured log output:
 *   ACCEPT_OK  | Time: <epoch> | NodeID: <hex> | PayloadLen: <n>
 *   AUDIT_FAIL | Time: <epoch> | NodeID: <hex> | Reason: <reason>
 *   DROP       | Time: <epoch> | NodeID: <hex> | Reason: <reason>
 */

#include "s_ipv4_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <inttypes.h>

/* ── Demo key material (must match client) ──────────────────────── */
static const uint8_t DEMO_NODE_ID[S_IPV4_NODE_ID_LEN] =
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

static const uint8_t DEMO_EPOCH_KEY[EPOCH_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

static void die(const char *msg) { perror(msg); exit(1); }

/* Format NodeID as hex string */
static void nodeid_hex(const uint8_t *raw, size_t raw_len,
                       char *buf, size_t buf_len, size_t pkt_len)
{
    if (pkt_len < 1 + S_IPV4_NODE_ID_LEN) {
        snprintf(buf, buf_len, "N/A");
        return;
    }
    /* skip s_flag byte */
    const uint8_t *nid = raw + 1;
    snprintf(buf, buf_len,
             "%02X%02X%02X%02X%02X%02X%02X%02X",
             nid[0], nid[1], nid[2], nid[3],
             nid[4], nid[5], nid[6], nid[7]);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <port> <ENFORCE|AUDIT>\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    server_mode_t mode = MODE_ENFORCE;
    if (strcasecmp(argv[2], "AUDIT") == 0) mode = MODE_AUDIT;

    /* Register demo node */
    keystore_register(DEMO_NODE_ID, DEMO_EPOCH_KEY);

    /* Init replay engine */
    replay_state_t rs;
    replay_init(&rs);

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) die("socket");

    /* Allow rapid port reuse between test runs */
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");

    printf("S-IPv4 server listening on :%d  [mode=%s]\n",
           port, mode == MODE_AUDIT ? "AUDIT" : "ENFORCE");
    fflush(stdout);

    uint8_t buf[65536];
    for (;;) {
        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &src_len);
        if (n <= 0) continue;

        time_t now = time(NULL);
        char nid_str[32];
        nodeid_hex(buf, sizeof(nid_str), nid_str, sizeof(nid_str), (size_t)n);

        const uint8_t *payload     = NULL;
        size_t         payload_len = 0;

        shim_result_t result = s_ipv4_verify_packet(
            buf, (size_t)n, &rs, &payload, &payload_len);

        if (result == SHIM_ACCEPT) {
            /* — Accepted — */
            printf("ACCEPT_OK  | Time: %ld | NodeID: %s | PayloadLen: %zu",
                   (long)now, nid_str, payload_len);
            if (payload_len > 0 && payload_len < 1024) {
                printf(" | Payload: \"%.*s\"", (int)payload_len, payload);
            }
            printf("\n");
            fflush(stdout);

        } else if (mode == MODE_AUDIT) {
            /* — AUDIT: log but deliver — */
            /* Even on failure, we expose the raw payload after the header */
            size_t raw_payload_len = 0;
            const uint8_t *raw_payload = NULL;
            if ((size_t)n > sizeof(s_ipv4_header_t)) {
                raw_payload     = buf + sizeof(s_ipv4_header_t);
                raw_payload_len = (size_t)n - sizeof(s_ipv4_header_t);
            }

            printf("AUDIT_FAIL | Time: %ld | NodeID: %s | Reason: %s",
                   (long)now, nid_str, shim_result_str(result));
            if (raw_payload_len > 0 && raw_payload_len < 1024) {
                printf(" | Payload: \"%.*s\"",
                       (int)raw_payload_len, raw_payload);
            }
            printf("\n");
            fflush(stdout);

        } else {
            /* — ENFORCE: silent drop — */
            printf("DROP       | Time: %ld | NodeID: %s | Reason: %s\n",
                   (long)now, nid_str, shim_result_str(result));
            fflush(stdout);
        }
    }

    close(sock);
    return 0;
}

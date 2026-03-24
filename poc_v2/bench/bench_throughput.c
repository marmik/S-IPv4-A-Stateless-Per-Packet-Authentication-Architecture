/*
 * bench_throughput.c — Loopback UDP throughput benchmark (V2)
 *
 * Measures packets/sec and Mbps with and without S-IPv4 V2 header.
 * Uses a forked sender/receiver pair over localhost.
 *
 * Runs at N = 10000, 100000, 1000000.
 *
 * Output format (one line per run):
 *   THROUGHPUT_BENCH <N> <mode> <pps> <mbps> <total_sec>
 *   mode = "SIPV4" or "RAW"
 */

#include "../s_ipv4_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <inttypes.h>

#define PAYLOAD_SIZE 128
#define BASE_PORT    19900

/* ── Portable htobe64 ───────────────────────────────────────────── */
#ifdef __APPLE__
#  include <libkern/OSByteOrder.h>
#  define htobe64_s(x)  OSSwapHostToBigInt64(x)
#else
#  include <endian.h>
#  define htobe64_s(x)  htobe64(x)
#endif

static double timespec_sec(struct timespec *start, struct timespec *end) {
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_nsec - start->tv_nsec) / 1e9;
}

/* ── Demo key material (V2: use crypto_init-derived keys) ──────── */
static uint8_t NODE_ID[S_IPV4_NODE_ID_LEN];
static uint8_t EPOCH_KEY_DATA[S_IPV4_KEY_LEN];
static const uint8_t MASTER_KEY[S_IPV4_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

/*
 * run_throughput_test — send N packets via loopback
 */
static double run_throughput_test(int N, int with_sipv4, int port)
{
    uint8_t payload[PAYLOAD_SIZE];
    memset(payload, 0xEF, PAYLOAD_SIZE);

    /* ── Receiver (child process) ──────────────────────────────── */
    pid_t child = fork();
    if (child == 0) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
        int rcvbuf = 8 * 1024 * 1024;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        struct sockaddr_in addr = {0};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(port);
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("receiver bind");
            _exit(1);
        }

        uint8_t buf[65536];
        for (int i = 0; i < N; i++) {
            recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
        }
        close(sock);
        _exit(0);
    }

    /* ── Sender (parent) ───────────────────────────────────────── */
    usleep(100000); /* 100 ms for receiver to bind */

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int sndbuf = 8 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    size_t pkt_len;
    uint8_t *pkt;

    if (with_sipv4) {
        pkt_len = sizeof(s_ipv4_v2_header_t) + PAYLOAD_SIZE;
        pkt     = malloc(pkt_len);
        s_ipv4_v2_header_t hdr;
        s_ipv4_generate_header(NODE_ID, EPOCH_KEY_DATA,
                               payload, PAYLOAD_SIZE, &hdr, 0, 0);
        memcpy(pkt, &hdr, sizeof(s_ipv4_v2_header_t));
        memcpy(pkt + sizeof(s_ipv4_v2_header_t), payload, PAYLOAD_SIZE);
    } else {
        pkt_len = PAYLOAD_SIZE;
        pkt     = malloc(pkt_len);
        memcpy(pkt, payload, PAYLOAD_SIZE);
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("connect");
        exit(1);
    }

    for (int i = 0; i < N; i++) {
        if (with_sipv4) {
            s_ipv4_v2_header_t hdr;
            s_ipv4_generate_header(NODE_ID, EPOCH_KEY_DATA,
                                   payload, PAYLOAD_SIZE, &hdr, 0, 0);
            memcpy(pkt, &hdr, sizeof(s_ipv4_v2_header_t));
        }
        send(sock, pkt, pkt_len, 0);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = timespec_sec(&t0, &t1);

    free(pkt);
    close(sock);
    waitpid(child, NULL, 0);

    return elapsed;
}

int main(void)
{
    /* Initialize V2 crypto subsystem */
    crypto_init(MASTER_KEY);
    /* Derive epoch_key first, then node_id from epoch_key (matches crypto_init order) */
    sipv4_hkdf_derive_epoch_key(MASTER_KEY, 1, EPOCH_KEY_DATA);
    sipv4_derive_node_id(EPOCH_KEY_DATA, NODE_ID);

    int test_sizes[] = {10000, 100000, 1000000};
    int num_tests    = 3;

    fprintf(stderr,
        "\n╔══════════════════════════════════════════════════╗\n"
        "║  Throughput Benchmark — Loopback UDP (V2)       ║\n"
        "╚══════════════════════════════════════════════════╝\n\n");

    for (int t = 0; t < num_tests; t++) {
        int N    = test_sizes[t];
        int port = BASE_PORT + t * 2;

        fprintf(stderr, "  [N=%d] Running RAW UDP...\n", N);
        double raw_sec = run_throughput_test(N, 0, port);
        double raw_pps = N / raw_sec;
        double raw_mbps = (N * (double)PAYLOAD_SIZE * 8.0) / (raw_sec * 1e6);

        fprintf(stderr, "  [N=%d] Running S-IPv4 V2 UDP...\n", N);
        double sipv4_sec = run_throughput_test(N, 1, port + 1);
        double sipv4_pps = N / sipv4_sec;
        size_t sipv4_pkt = sizeof(s_ipv4_v2_header_t) + PAYLOAD_SIZE;
        double sipv4_mbps = (N * (double)sipv4_pkt * 8.0) / (sipv4_sec * 1e6);

        double overhead_pct = ((raw_sec > 0) ?
            ((sipv4_sec - raw_sec) / raw_sec) * 100.0 : 0.0);
        double bw_overhead = (((double)sipv4_pkt - PAYLOAD_SIZE)
                              / (double)PAYLOAD_SIZE) * 100.0;

        printf("THROUGHPUT_BENCH\t%d\tRAW\t%.0f\t%.2f\t%.4f\n",
               N, raw_pps, raw_mbps, raw_sec);
        printf("THROUGHPUT_BENCH\t%d\tSIPV4\t%.0f\t%.2f\t%.4f\n",
               N, sipv4_pps, sipv4_mbps, sipv4_sec);
        printf("THROUGHPUT_OVERHEAD\t%d\t%.2f\t%.2f\n",
               N, overhead_pct, bw_overhead);

        fprintf(stderr,
            "  ┌──────────────────────────────────────────────┐\n"
            "  │ N = %-10d                               │\n"
            "  │ RAW:   %10.0f pps  %8.2f Mbps  %6.3fs │\n"
            "  │ S-IPv4:%10.0f pps  %8.2f Mbps  %6.3fs │\n"
            "  │ Time overhead: %+.1f%%                       │\n"
            "  │ BW overhead:   %.1f%% (%zu → %d bytes/pkt)   │\n"
            "  └──────────────────────────────────────────────┘\n\n",
            N,
            raw_pps, raw_mbps, raw_sec,
            sipv4_pps, sipv4_mbps, sipv4_sec,
            overhead_pct,
            bw_overhead, sipv4_pkt, PAYLOAD_SIZE);
    }

    return 0;
}

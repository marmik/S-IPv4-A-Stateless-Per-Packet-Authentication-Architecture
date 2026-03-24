/*
 * bench_verify.c — Full S-IPv4 shim verification path latency benchmark
 *
 * Measures: bounds check → magic → NodeID lookup → timestamp →
 *           HMAC recompute → CRYPTO_memcmp → Bloom filter
 *
 * 100,000 samples recorded, percentiles reported.
 *
 * Output: VERIFY_BENCH <mean> <std> <min> <max> <p50> <p95> <p99>
 */

#include "../s_ipv4_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>

#define NUM_SAMPLES  100000
#define PAYLOAD_SIZE 128

/* ── Portable htobe64 ───────────────────────────────────────────── */
#ifdef __APPLE__
#  include <libkern/OSByteOrder.h>
#  define htobe64_s(x)  OSSwapHostToBigInt64(x)
#else
#  include <endian.h>
#  define htobe64_s(x)  htobe64(x)
#endif

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static double timespec_us(struct timespec *start, struct timespec *end) {
    return (double)(end->tv_sec - start->tv_sec) * 1e6 +
           (double)(end->tv_nsec - start->tv_nsec) / 1e3;
}

int main(void)
{
    /* ── Setup ──────────────────────────────────────────────────── */
    static const uint8_t node_id[S_IPV4_NODE_ID_LEN] =
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    static const uint8_t epoch_key[EPOCH_KEY_LEN] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    uint8_t payload[PAYLOAD_SIZE];
    memset(payload, 0xCD, PAYLOAD_SIZE);

    keystore_register(node_id, epoch_key);

    replay_state_t rs;
    replay_init(&rs);

    /* Pre-build N unique valid packets (each with a distinct nonce) */
    size_t pkt_len = sizeof(s_ipv4_header_t) + PAYLOAD_SIZE;
    uint8_t **packets = malloc(NUM_SAMPLES * sizeof(uint8_t *));
    if (!packets) { perror("malloc"); return 1; }

    for (int i = 0; i < NUM_SAMPLES; i++) {
        packets[i] = malloc(pkt_len);
        s_ipv4_header_t hdr;
        /* use distinct nonce per packet so Bloom filter doesn't reject */
        s_ipv4_generate_header(node_id, epoch_key,
                               payload, PAYLOAD_SIZE, &hdr, 0, 0);
        memcpy(packets[i], &hdr, sizeof(s_ipv4_header_t));
        memcpy(packets[i] + sizeof(s_ipv4_header_t), payload, PAYLOAD_SIZE);
    }

    double *samples = malloc(NUM_SAMPLES * sizeof(double));
    if (!samples) { perror("malloc"); return 1; }

    /* ── Warm-up ────────────────────────────────────────────────── */
    /* Use a separate replay state for warm-up to not pollute Bloom filter */
    replay_state_t rs_warmup;
    replay_init(&rs_warmup);
    for (int i = 0; i < 100; i++) {
        const uint8_t *pl; size_t pl_len;
        s_ipv4_verify_packet(packets[i], pkt_len, &rs_warmup, &pl, &pl_len);
    }

    /* ── Timed run ──────────────────────────────────────────────── */
    fprintf(stderr, "Running %d full verification samples...\n", NUM_SAMPLES);

    /* Fresh replay state for the actual benchmark */
    replay_state_t rs_bench;
    replay_init(&rs_bench);

    for (int i = 0; i < NUM_SAMPLES; i++) {
        const uint8_t *pl; size_t pl_len;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        shim_result_t r = s_ipv4_verify_packet(packets[i], pkt_len,
                                               &rs_bench, &pl, &pl_len);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        samples[i] = timespec_us(&t0, &t1);
        if (r != SHIM_ACCEPT) {
            fprintf(stderr, "  WARN: packet %d got result %d (%s)\n",
                    i, r, shim_result_str(r));
        }
    }

    /* ── Statistics ─────────────────────────────────────────────── */
    qsort(samples, NUM_SAMPLES, sizeof(double), cmp_double);

    double sum = 0, sum_sq = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        sum    += samples[i];
        sum_sq += samples[i] * samples[i];
    }
    double mean = sum / NUM_SAMPLES;
    double var  = (sum_sq / NUM_SAMPLES) - (mean * mean);
    double std  = sqrt(var > 0 ? var : 0);
    double min  = samples[0];
    double max  = samples[NUM_SAMPLES - 1];
    double p50  = samples[(int)(NUM_SAMPLES * 0.50)];
    double p95  = samples[(int)(NUM_SAMPLES * 0.95)];
    double p99  = samples[(int)(NUM_SAMPLES * 0.99)];

    printf("VERIFY_BENCH\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n",
           mean, std, min, max, p50, p95, p99);

    fprintf(stderr,
        "\n╔══════════════════════════════════════════════════╗\n"
        "║  Full Verification Latency (µs)                 ║\n"
        "╠══════════════════════════════════════════════════╣\n"
        "║  Mean:   %10.3f µs                           ║\n"
        "║  StdDev: %10.3f µs                           ║\n"
        "║  Min:    %10.3f µs                           ║\n"
        "║  Max:    %10.3f µs                           ║\n"
        "║  P50:    %10.3f µs                           ║\n"
        "║  P95:    %10.3f µs                           ║\n"
        "║  P99:    %10.3f µs                           ║\n"
        "╚══════════════════════════════════════════════════╝\n",
        mean, std, min, max, p50, p95, p99);

    /* ── CSV for plotting ───────────────────────────────────────── */
    FILE *csv = fopen("verify_samples.csv", "w");
    if (csv) {
        fprintf(csv, "sample_idx,latency_us\n");
        for (int i = 0; i < NUM_SAMPLES; i++)
            fprintf(csv, "%d,%.6f\n", i, samples[i]);
        fclose(csv);
        fprintf(stderr, "Raw samples written to bench/verify_samples.csv\n");
    }

    replay_destroy(&rs_warmup);
    replay_destroy(&rs_bench);

    for (int i = 0; i < NUM_SAMPLES; i++) free(packets[i]);
    free(packets);
    free(samples);
    return 0;
}

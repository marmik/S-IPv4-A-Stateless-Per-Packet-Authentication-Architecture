/*
 * bench_verify.c — Full S-IPv4 V2 shim verification path latency benchmark
 *
 * Measures: bounds check → version flag → NodeID lookup → timestamp →
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
    /* ── Setup — use V2 crypto_init to derive node_id from key ──── */
    static const uint8_t master_key[S_IPV4_KEY_LEN] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    uint8_t payload[PAYLOAD_SIZE];
    memset(payload, 0xCD, PAYLOAD_SIZE);

    /* Initialize V2 crypto subsystem (derives node_id, epoch key) */
    crypto_init(master_key);

    /* Get the derived epoch key and node_id — must match crypto_init order:
       crypto_init derives epoch_key from master, then node_id from epoch_key */
    uint8_t epoch_key[S_IPV4_KEY_LEN];
    sipv4_hkdf_derive_epoch_key(master_key, 1, epoch_key);
    uint8_t node_id[S_IPV4_NODE_ID_LEN];
    sipv4_derive_node_id(epoch_key, node_id);

    tiered_bloom_t tb;
    tiered_bloom_init(&tb);

    /* Pre-build N unique valid packets (each with a distinct nonce) */
    size_t pkt_len = sizeof(s_ipv4_v2_header_t) + PAYLOAD_SIZE;
    uint8_t **packets = malloc(NUM_SAMPLES * sizeof(uint8_t *));
    if (!packets) { perror("malloc"); return 1; }

    for (int i = 0; i < NUM_SAMPLES; i++) {
        packets[i] = malloc(pkt_len);
        s_ipv4_v2_header_t hdr;
        s_ipv4_generate_header(node_id, epoch_key,
                               payload, PAYLOAD_SIZE, &hdr, 0, 0);
        memcpy(packets[i], &hdr, sizeof(s_ipv4_v2_header_t));
        memcpy(packets[i] + sizeof(s_ipv4_v2_header_t), payload, PAYLOAD_SIZE);
    }

    double *samples = malloc(NUM_SAMPLES * sizeof(double));
    if (!samples) { perror("malloc"); return 1; }

    /* ── Warm-up ────────────────────────────────────────────────── */
    tiered_bloom_t tb_warmup;
    tiered_bloom_init(&tb_warmup);
    for (int i = 0; i < 100; i++) {
        const uint8_t *pl; size_t pl_len;
        s_ipv4_verify_packet(packets[i], pkt_len, &tb_warmup, &pl, &pl_len);
    }

    /* ── Timed run ──────────────────────────────────────────────── */
    fprintf(stderr, "Running %d full verification samples...\n", NUM_SAMPLES);

    tiered_bloom_t tb_bench;
    tiered_bloom_init(&tb_bench);

    int replay_fp_count = 0;
    int error_count = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        const uint8_t *pl; size_t pl_len;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        shim_result_t r = s_ipv4_verify_packet(packets[i], pkt_len,
                                               &tb_bench, &pl, &pl_len);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        samples[i] = timespec_us(&t0, &t1);
        if (r == SHIM_DROP_REPLAY) {
            replay_fp_count++;  /* Expected: Tier 1 (50k) saturates at 100k nonces */
        } else if (r != SHIM_ACCEPT) {
            error_count++;
            if (error_count <= 5) {
                fprintf(stderr, "  ERROR: packet %d got result %d (%s)\n",
                        i, r, shim_result_str(r));
            }
        }
    }
    if (replay_fp_count > 0) {
        fprintf(stderr, "  Note: %d/%d packets hit Bloom filter false positive "
                "(Tier 1 cap=%lu, expected at this volume)\n",
                replay_fp_count, NUM_SAMPLES, (unsigned long)BF_TIER1_CAPACITY);
    }
    if (error_count > 0) {
        fprintf(stderr, "  WARNING: %d packets had real verification failures\n",
                error_count);
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

    tiered_bloom_free(&tb);
    tiered_bloom_free(&tb_warmup);
    tiered_bloom_free(&tb_bench);

    for (int i = 0; i < NUM_SAMPLES; i++) free(packets[i]);
    free(packets);
    free(samples);
    return 0;
}

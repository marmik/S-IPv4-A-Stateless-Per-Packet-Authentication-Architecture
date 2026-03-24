/*
 * bench_crypto.c — HMAC token generation latency benchmark (S-IPv4 V2)
 *
 * Calls compute_token() 100,000 times, records each sample with
 * clock_gettime(CLOCK_MONOTONIC), then prints summary statistics.
 *
 * Output format (tab-separated for LaTeX consumption):
 *   CRYPTO_BENCH <mean_us> <std_us> <min_us> <max_us> <p50_us> <p95_us> <p99_us>
 *
 * Also writes raw samples to bench/crypto_samples.csv for plotting.
 *
 * V2 COMPLIANCE NOTE:
 *   This file contains zero deprecated OpenSSL API references (no HMAC_CTX_new,
 *   HMAC_Init_ex, HMAC_Update, HMAC_Final, or HMAC_CTX_free).
 *   All cryptographic operations go through compute_token() in poc_v2/crypto_core.c,
 *   which is implemented exclusively on OpenSSL 3.0 EVP_MAC primitives.
 *   The build guard below enforces that this file cannot be linked against
 *   the V1 crypto_core (which used the deprecated HMAC_CTX API).
 */

#include "../crypto_core.h"
#include "../s_ipv4.h"

/* ── V2 build guard ─────────────────────────────────────────────────
 * S_IPV4_CRYPTO_V2 is defined in poc_v2/crypto_core.h.
 * If this bench is accidentally built against the V1 crypto_core.h
 * (which does NOT define this macro), the build fails immediately
 * rather than silently linking deprecated HMAC_CTX code.
 * ────────────────────────────────────────────────────────────────── */
#ifndef S_IPV4_CRYPTO_V2
#  error "bench_crypto.c must be built against poc_v2/crypto_core.h (V2 EVP_MAC). " \
         "Do not link against poc/crypto_core.h (V1 HMAC_CTX). " \
         "Run: cd poc_v2/bench && make clean && make"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>

#define NUM_SAMPLES  100000
#define PAYLOAD_SIZE 128

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
    /* ── Key / payload setup ────────────────────────────────────── */
    static const uint8_t epoch_key[S_IPV4_KEY_LEN] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };

    uint8_t payload[PAYLOAD_SIZE];
    memset(payload, 0xAB, PAYLOAD_SIZE);

    uint8_t out_hmac[16];                          /* S_IPV4_HMAC_LEN = 16 */
    uint64_t ts    = (uint64_t)time(NULL);
    uint64_t nonce = 0x1234567890ABCDEFULL;

    double *samples = malloc(NUM_SAMPLES * sizeof(double));
    if (!samples) { perror("malloc"); return 1; }

    /* ── Warm-up (100 iterations) ───────────────────────────────── */
    for (int i = 0; i < 100; i++) {
        crypto_compute_token(epoch_key, ts, nonce + (uint64_t)i,
                      payload, PAYLOAD_SIZE, out_hmac);
    }

    /* ── Timed run ──────────────────────────────────────────────── */
    fprintf(stderr, "Running %d HMAC token generation samples...\n", NUM_SAMPLES);
    for (int i = 0; i < NUM_SAMPLES; i++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        crypto_compute_token(epoch_key, ts, nonce + (uint64_t)i,
                      payload, PAYLOAD_SIZE, out_hmac);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        samples[i] = timespec_us(&t0, &t1);
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

    int p50_idx = (int)(NUM_SAMPLES * 0.50);
    int p95_idx = (int)(NUM_SAMPLES * 0.95);
    int p99_idx = (int)(NUM_SAMPLES * 0.99);
    double p50 = samples[p50_idx];
    double p95 = samples[p95_idx];
    double p99 = samples[p99_idx];

    /* ── Print structured result ────────────────────────────────── */
    printf("CRYPTO_BENCH\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n",
           mean, std, min, max, p50, p95, p99);

    fprintf(stderr,
        "\n╔══════════════════════════════════════════════════╗\n"
        "║  HMAC Token Generation Latency (µs)             ║\n"
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

    /* ── Write raw samples CSV for plotting ─────────────────────── */
    FILE *csv = fopen("crypto_samples.csv", "w");
    if (csv) {
        fprintf(csv, "sample_idx,latency_us\n");
        for (int i = 0; i < NUM_SAMPLES; i++) {
            fprintf(csv, "%d,%.6f\n", i, samples[i]);
        }
        fclose(csv);
        fprintf(stderr, "Raw samples written to bench/crypto_samples.csv\n");
    }

    free(samples);
    return 0;
}

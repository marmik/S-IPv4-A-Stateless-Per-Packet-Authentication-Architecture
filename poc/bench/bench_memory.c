/*
 * bench_memory.c — Bloom filter memory footprint measurement
 *
 * Measures the memory consumed by the dual-window Bloom filter at
 * 10k, 100k, 500k, and 1M tracked nonces.
 *
 * Output: MEMORY_BENCH <nonces> <filter_kb> <total_kb> <fp_rate> <fill_pct>
 */

#include "../replay_protection.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>

int main(void)
{
    int test_sizes[] = {10000, 100000, 500000, 1000000};
    int num_tests    = 4;

    /*
     * The Bloom filter has a fixed memory footprint regardless of
     * how many elements are inserted — that is the whole point.
     *
     * Actual heap allocation per filter = BLOOM_SIZE_BYTES.
     * The struct itself just holds a pointer + metadata.
     */

    double filter_kb = (double)BLOOM_SIZE_BYTES / 1024.0;
    double total_kb  = filter_kb * 2.0;   /* dual-window */

    fprintf(stderr,
        "\n╔══════════════════════════════════════════════════════════╗\n"
        "║  Bloom Filter Memory Footprint                          ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║  Design capacity: %d nonces (FP target: %.1f%%)      ║\n"
        "║  m = %llu bits,  k = %d hashes                       ║\n"
        "║  Single filter:  %.2f KiB (%d bytes)                  ║\n"
        "║  Dual window:    %.2f KiB                              ║\n"
        "╠══════════════════════════════════════════════════════════╣\n",
        BLOOM_CAPACITY,
        BLOOM_FP_RATE * 100.0,
        (unsigned long long)BLOOM_SIZE_BITS, BLOOM_NUM_HASHES,
        filter_kb, BLOOM_SIZE_BYTES,
        total_kb);

    for (int t = 0; t < num_tests; t++) {
        int N = test_sizes[t];

        replay_state_t rs;
        replay_init(&rs);

        /* Insert N nonces */
        for (int i = 0; i < N; i++) {
            nonce_check_and_insert(&rs, (uint64_t)i * 0x9E3779B97F4A7C15ULL);
        }

        /* Compute actual bit usage in current filter (heap-allocated) */
        int bits_set = 0;
        for (int b = 0; b < BLOOM_SIZE_BYTES; b++) {
            uint8_t v = rs.current.bits[b];
            while (v) { bits_set += (v & 1); v >>= 1; }
        }
        double fill_pct = (double)bits_set / (double)BLOOM_SIZE_BITS * 100.0;

        /* Theoretical false positive rate: (1 - e^(-kn/m))^k */
        double k = BLOOM_NUM_HASHES;
        double m = (double)BLOOM_SIZE_BITS;
        double exponent = -k * N / m;
        double fp_rate  = 1.0;
        for (int i = 0; i < BLOOM_NUM_HASHES; i++) {
            fp_rate *= (1.0 - exp(exponent));
        }

        printf("MEMORY_BENCH\t%d\t%.2f\t%.2f\t%.6f\t%.2f\n",
               N, filter_kb, total_kb, fp_rate * 100.0, fill_pct);

        fprintf(stderr,
            "║  N = %-10d | Fill: %5.2f%% | FP rate: %.6f%% ║\n",
            N, fill_pct, fp_rate * 100.0);

        replay_destroy(&rs);
    }

    fprintf(stderr,
        "╚══════════════════════════════════════════════════════════╝\n\n");

    return 0;
}

/*
 * bench_memory.c — V2 Tiered Bloom filter memory footprint measurement
 *
 * Measures the memory consumed by the three-tier Bloom filter system
 * at 10k, 100k, 500k, and 1M tracked nonces.
 *
 * Output: MEMORY_BENCH <nonces> <tier1_kb> <tier2_kb> <tier3_kb> <total_kb> <fill_pct>
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

    /* Compute fixed memory footprint per tier */
    double tier1_kb = (double)(BF_TIER1_CAPACITY * 10 + 7) / 8.0 / 1024.0;
    double tier2_kb = (double)(BF_TIER2_CAPACITY * 10 + 7) / 8.0 / 1024.0;
    double tier3_kb = (double)(BF_TIER3_CAPACITY * 10 + 7) / 8.0 / 1024.0;
    double total_kb = tier1_kb + tier2_kb + tier3_kb;

    fprintf(stderr,
        "\n╔══════════════════════════════════════════════════════════╗\n"
        "║  V2 Tiered Bloom Filter Memory Footprint                ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║  Tier 1: %10.2f KiB  (capacity: %lu nonces)        ║\n"
        "║  Tier 2: %10.2f KiB  (capacity: %lu nonces)       ║\n"
        "║  Tier 3: %10.2f KiB  (capacity: %lu nonces)     ║\n"
        "║  Total:  %10.2f KiB  (%d hash functions)              ║\n"
        "╠══════════════════════════════════════════════════════════╣\n",
        tier1_kb, (unsigned long)BF_TIER1_CAPACITY,
        tier2_kb, (unsigned long)BF_TIER2_CAPACITY,
        tier3_kb, (unsigned long)BF_TIER3_CAPACITY,
        total_kb, BF_HASH_FUNCS);

    for (int t = 0; t < num_tests; t++) {
        int N = test_sizes[t];

        tiered_bloom_t tb;
        tiered_bloom_init(&tb);

        /* Insert N nonces into the tiered system */
        for (int i = 0; i < N; i++) {
            tiered_bloom_insert(&tb, (uint64_t)i * 0x9E3779B97F4A7C15ULL);
        }

        double fill = tiered_bloom_fill_pct(&tb);

        /* Theoretical FP rate for Tier 2 (primary): (1 - e^(-kn/m))^k */
        double k = BF_HASH_FUNCS;
        double m = (double)(BF_TIER2_CAPACITY * 10);
        double exponent = -k * N / m;
        double fp_rate  = 1.0;
        for (int i = 0; i < BF_HASH_FUNCS; i++) {
            fp_rate *= (1.0 - exp(exponent));
        }

        printf("MEMORY_BENCH\t%d\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.6f\n",
               N, tier1_kb, tier2_kb, tier3_kb, total_kb, fill, fp_rate * 100.0);

        fprintf(stderr,
            "║  N = %-10d | Fill: %5.2f%% | FP rate: %.6f%% ║\n",
            N, fill, fp_rate * 100.0);

        tiered_bloom_free(&tb);
    }

    fprintf(stderr,
        "╚══════════════════════════════════════════════════════════╝\n\n");

    return 0;
}

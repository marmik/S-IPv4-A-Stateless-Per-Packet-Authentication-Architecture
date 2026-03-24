/*
 * bench_adversarial.c — S-IPv4 V2 Adversarial Benchmark
 *
 * Tests four adversarial attack scenarios:
 *   1. Random node_id flood (tests early-exit performance)
 *   2. Valid node_id + invalid HMAC (tests full verification rejection)
 *   3. Bloom filter saturation (tests behavior beyond Tier 1 capacity)
 *   4. Timestamp manipulation (tests window rejection performance)
 *
 * Measures rejection throughput (packets/sec) for each scenario.
 */

#include "s_ipv4.h"
#include "s_ipv4_shim.h"
#include "crypto_core.h"
#include "replay_protection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

#define NUM_PACKETS  100000
#define PAYLOAD_SIZE 128

static const uint8_t MASTER_KEY[S_IPV4_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

static double time_diff(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1e9;
}

static double get_cpu_usage(struct rusage *start, struct rusage *end) {
    double user = (end->ru_utime.tv_sec - start->ru_utime.tv_sec)
                + (end->ru_utime.tv_usec - start->ru_utime.tv_usec) / 1e6;
    double sys  = (end->ru_stime.tv_sec - start->ru_stime.tv_sec)
                + (end->ru_stime.tv_usec - start->ru_stime.tv_usec) / 1e6;
    return user + sys;
}

int main(void)
{
    crypto_init(MASTER_KEY);
    uint8_t epoch_key[S_IPV4_KEY_LEN];
    sipv4_hkdf_derive_epoch_key(MASTER_KEY, 1, epoch_key);
    uint8_t node_id[S_IPV4_NODE_ID_LEN];
    sipv4_derive_node_id(epoch_key, node_id);

    uint8_t payload[PAYLOAD_SIZE];
    memset(payload, 0xAB, PAYLOAD_SIZE);

    tiered_bloom_t tb;
    tiered_bloom_init(&tb);

    size_t pkt_len = sizeof(s_ipv4_v2_header_t) + PAYLOAD_SIZE;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  S-IPv4 V2 Adversarial Benchmark (%d packets each)   ║\n", NUM_PACKETS);
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* ── Scenario 1: Random node_id flood ──────────────────────────── */
    {
        printf("  [1/4] Random node_id flood (early-exit test)\n");
        tiered_bloom_t tb1;
        tiered_bloom_init(&tb1);

        struct timespec t0, t1;
        struct rusage r0, r1;
        getrusage(RUSAGE_SELF, &r0);
        clock_gettime(CLOCK_MONOTONIC, &t0);

        int dropped = 0;
        for (int i = 0; i < NUM_PACKETS; i++) {
            s_ipv4_v2_header_t hdr;
            memset(&hdr, 0, sizeof(hdr));
            hdr.s_flag = S_IPV4_FLAG_V2;
            /* Random fake node_id */
            for (int j = 0; j < 8; j++) hdr.node_id[j] = (uint8_t)(i ^ j ^ 0xDE);
            uint8_t buf[pkt_len];
            memcpy(buf, &hdr, sizeof(hdr));
            memcpy(buf + sizeof(hdr), payload, PAYLOAD_SIZE);
            const uint8_t *pl; size_t pl_len;
            shim_result_t r = s_ipv4_verify_packet(buf, pkt_len, &tb1, &pl, &pl_len);
            if (r != SHIM_ACCEPT) dropped++;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        getrusage(RUSAGE_SELF, &r1);
        double elapsed = time_diff(&t0, &t1);
        double cpu = get_cpu_usage(&r0, &r1);
        printf("        Dropped: %d/%d  |  %.0f pps  |  CPU: %.3fs  |  CPU%%: %.1f%%\n\n",
               dropped, NUM_PACKETS, NUM_PACKETS/elapsed, cpu, (cpu/elapsed)*100);

        fprintf(stdout, "ADVERSARIAL\t1_random_node\t%d\t%d\t%.0f\t%.3f\t%.1f\n",
                NUM_PACKETS, dropped, NUM_PACKETS/elapsed, cpu, (cpu/elapsed)*100);
        tiered_bloom_free(&tb1);
    }

    /* ── Scenario 2: Valid node_id + invalid HMAC ──────────────────── */
    {
        printf("  [2/4] Valid node_id + invalid HMAC (full verify rejection)\n");
        tiered_bloom_t tb2;
        tiered_bloom_init(&tb2);

        struct timespec t0, t1;
        struct rusage r0, r1;
        getrusage(RUSAGE_SELF, &r0);
        clock_gettime(CLOCK_MONOTONIC, &t0);

        int dropped = 0;
        for (int i = 0; i < NUM_PACKETS; i++) {
            s_ipv4_v2_header_t hdr;
            s_ipv4_generate_header(node_id, epoch_key, payload, PAYLOAD_SIZE, &hdr, 0, 0);
            hdr.hmac[0] ^= 0xFF; /* Corrupt the HMAC */
            uint8_t buf[pkt_len];
            memcpy(buf, &hdr, sizeof(hdr));
            memcpy(buf + sizeof(hdr), payload, PAYLOAD_SIZE);
            const uint8_t *pl; size_t pl_len;
            shim_result_t r = s_ipv4_verify_packet(buf, pkt_len, &tb2, &pl, &pl_len);
            if (r != SHIM_ACCEPT) dropped++;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        getrusage(RUSAGE_SELF, &r1);
        double elapsed = time_diff(&t0, &t1);
        double cpu = get_cpu_usage(&r0, &r1);
        printf("        Dropped: %d/%d  |  %.0f pps  |  CPU: %.3fs  |  CPU%%: %.1f%%\n\n",
               dropped, NUM_PACKETS, NUM_PACKETS/elapsed, cpu, (cpu/elapsed)*100);

        fprintf(stdout, "ADVERSARIAL\t2_bad_hmac\t%d\t%d\t%.0f\t%.3f\t%.1f\n",
                NUM_PACKETS, dropped, NUM_PACKETS/elapsed, cpu, (cpu/elapsed)*100);
        tiered_bloom_free(&tb2);
    }

    /* ── Scenario 3: Bloom filter saturation ───────────────────────── */
    {
        printf("  [3/4] Bloom filter saturation (Tier 1 overflow test)\n");
        tiered_bloom_t tb3;
        tiered_bloom_init(&tb3);

        struct timespec t0, t1;
        struct rusage r0, r1;

        /* Pre-fill Tier 1 past capacity */
        for (uint64_t i = 0; i < BF_TIER1_CAPACITY + 10000; i++) {
            tiered_bloom_insert(&tb3, i + 1000000ULL);
        }
        double fill_before = tiered_bloom_fill_pct(&tb3);
        printf("        Pre-fill: %.1f%% of Tier 2 capacity\n", fill_before);

        getrusage(RUSAGE_SELF, &r0);
        clock_gettime(CLOCK_MONOTONIC, &t0);

        int accepted = 0, replay_fp = 0;
        for (int i = 0; i < NUM_PACKETS; i++) {
            s_ipv4_v2_header_t hdr;
            s_ipv4_generate_header(node_id, epoch_key, payload, PAYLOAD_SIZE, &hdr, 0, 0);
            uint8_t buf[pkt_len];
            memcpy(buf, &hdr, sizeof(hdr));
            memcpy(buf + sizeof(hdr), payload, PAYLOAD_SIZE);
            const uint8_t *pl; size_t pl_len;
            shim_result_t r = s_ipv4_verify_packet(buf, pkt_len, &tb3, &pl, &pl_len);
            if (r == SHIM_ACCEPT) accepted++;
            else if (r == SHIM_DROP_REPLAY) replay_fp++;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        getrusage(RUSAGE_SELF, &r1);
        double elapsed = time_diff(&t0, &t1);
        double cpu = get_cpu_usage(&r0, &r1);
        printf("        Accepted: %d  FP replays: %d  |  %.0f pps  |  CPU%%: %.1f%%\n\n",
               accepted, replay_fp, NUM_PACKETS/elapsed, (cpu/elapsed)*100);

        fprintf(stdout, "ADVERSARIAL\t3_bloom_sat\t%d\t%d\t%.0f\t%.3f\t%.1f\n",
                NUM_PACKETS, replay_fp, NUM_PACKETS/elapsed, cpu, (cpu/elapsed)*100);
        tiered_bloom_free(&tb3);
    }

    /* ── Scenario 4: Expired timestamp flood ───────────────────────── */
    {
        printf("  [4/4] Expired timestamp flood (window rejection test)\n");
        tiered_bloom_t tb4;
        tiered_bloom_init(&tb4);

        struct timespec t0, t1;
        struct rusage r0, r1;
        getrusage(RUSAGE_SELF, &r0);
        clock_gettime(CLOCK_MONOTONIC, &t0);

        int dropped = 0;
        uint64_t old_ts = (uint64_t)time(NULL) - 600; /* 10 minutes ago */
        for (int i = 0; i < NUM_PACKETS; i++) {
            s_ipv4_v2_header_t hdr;
            s_ipv4_generate_header(node_id, epoch_key, payload, PAYLOAD_SIZE, &hdr, 0, old_ts);
            uint8_t buf[pkt_len];
            memcpy(buf, &hdr, sizeof(hdr));
            memcpy(buf + sizeof(hdr), payload, PAYLOAD_SIZE);
            const uint8_t *pl; size_t pl_len;
            shim_result_t r = s_ipv4_verify_packet(buf, pkt_len, &tb4, &pl, &pl_len);
            if (r != SHIM_ACCEPT) dropped++;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        getrusage(RUSAGE_SELF, &r1);
        double elapsed = time_diff(&t0, &t1);
        double cpu = get_cpu_usage(&r0, &r1);
        printf("        Dropped: %d/%d  |  %.0f pps  |  CPU: %.3fs  |  CPU%%: %.1f%%\n\n",
               dropped, NUM_PACKETS, NUM_PACKETS/elapsed, cpu, (cpu/elapsed)*100);

        fprintf(stdout, "ADVERSARIAL\t4_expired_ts\t%d\t%d\t%.0f\t%.3f\t%.1f\n",
                NUM_PACKETS, dropped, NUM_PACKETS/elapsed, cpu, (cpu/elapsed)*100);
        tiered_bloom_free(&tb4);
    }

    printf("🟢  Adversarial benchmark complete.\n\n");
    return 0;
}

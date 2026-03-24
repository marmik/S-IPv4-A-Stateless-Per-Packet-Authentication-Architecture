#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include <stdint.h>
#include <stddef.h>

/* ── Bloom filter capacity tiers ────────────────────────────────── */
#define BF_TIER1_CAPACITY   50000UL       /*  ~350 KiB — L1 fast path  */
#define BF_TIER2_CAPACITY   2000000UL     /*  ~7 MiB  — primary        */
#define BF_TIER3_CAPACITY   10000000UL    /* ~35 MiB  — flood overflow  */
#define BF_HASH_FUNCS       10

/* ── Adaptive window thresholds ─────────────────────────────────── */
#define WINDOW_NORMAL_SEC    5
#define WINDOW_ELEVATED_SEC  3
#define WINDOW_HIGH_SEC      1
#define WINDOW_EMERGENCY_MS  500
#define FILL_ELEVATED_PCT    20.0
#define FILL_HIGH_PCT        50.0
#define FILL_EMERGENCY_PCT   75.0
#define FILL_DEGRADED_PCT    80.0

/* ── Bloom filter struct ─────────────────────────────────────────── */
typedef struct {
    uint8_t  *bits;
    uint64_t  m_bits;
    uint32_t  k_funcs;
    uint64_t  capacity;
    uint64_t  insert_count;
} bloom_filter_t;

/* ── Three-tier system ───────────────────────────────────────────── */
typedef struct {
    bloom_filter_t tier1;
    bloom_filter_t tier2;
    bloom_filter_t tier3;
    int            tier3_active;
    int            degraded_mode;
    uint64_t       degraded_since_sec;
} tiered_bloom_t;

#ifdef SIPV4_TEST_MODE
void tiered_bloom_force_fill(tiered_bloom_t *tb, uint64_t count);
#endif

/* ── API ─────────────────────────────────────────────────────────── */
int  tiered_bloom_init(tiered_bloom_t *tb);
void tiered_bloom_free(tiered_bloom_t *tb);
int  tiered_bloom_check(tiered_bloom_t *tb, uint64_t nonce);
void tiered_bloom_insert(tiered_bloom_t *tb, uint64_t nonce);
double tiered_bloom_fill_pct(const tiered_bloom_t *tb);

uint32_t sipv4_adaptive_window_sec(double fill_pct);
uint32_t sipv4_adaptive_rotation_sec(double fill_pct);

int  replay_check_and_insert(tiered_bloom_t *tb,
                              uint64_t nonce, uint64_t timestamp);

#endif /* REPLAY_PROTECTION_H */

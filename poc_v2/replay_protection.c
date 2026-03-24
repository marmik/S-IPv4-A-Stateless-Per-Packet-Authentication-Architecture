#include "replay_protection.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

static uint64_t fnv1a_hash(uint64_t seed, uint64_t val) {
    uint64_t hash = 14695981039346656037ULL ^ seed;
    uint8_t *p = (uint8_t *)&val;
    for (int i=0; i<8; i++) {
        hash ^= p[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static int bf_init(bloom_filter_t *bf, uint64_t cap) {
    bf->capacity = cap;
    bf->m_bits = cap * 10;
    bf->k_funcs = BF_HASH_FUNCS;
    bf->insert_count = 0;
    bf->bits = calloc((bf->m_bits + 7) / 8, 1);
    return bf->bits ? 0 : -1;
}

static void bf_free(bloom_filter_t *bf) {
    if (bf->bits) free(bf->bits);
}

static int bf_check(const bloom_filter_t *bf, uint64_t nonce) {
    for (uint32_t i=0; i<bf->k_funcs; i++) {
        uint64_t id = fnv1a_hash(i, nonce) % bf->m_bits;
        if (!(bf->bits[id / 8] & (1 << (id % 8)))) {
            return 0; // Not seen
        }
    }
    return 1; // seen
}

static void bf_insert(bloom_filter_t *bf, uint64_t nonce) {
    for (uint32_t i=0; i<bf->k_funcs; i++) {
        uint64_t id = fnv1a_hash(i, nonce) % bf->m_bits;
        bf->bits[id / 8] |= (1 << (id % 8));
    }
    bf->insert_count++;
}

int tiered_bloom_init(tiered_bloom_t *tb) {
    memset(tb, 0, sizeof(*tb));
    if (bf_init(&tb->tier1, BF_TIER1_CAPACITY) != 0) return -1;
    if (bf_init(&tb->tier2, BF_TIER2_CAPACITY) != 0) return -1;
    if (bf_init(&tb->tier3, BF_TIER3_CAPACITY) != 0) return -1;
    return 0;
}

void tiered_bloom_free(tiered_bloom_t *tb) {
    bf_free(&tb->tier1);
    bf_free(&tb->tier2);
    bf_free(&tb->tier3);
}

double tiered_bloom_fill_pct(const tiered_bloom_t *tb) {
    return (double)tb->tier2.insert_count / (double)tb->tier2.capacity * 100.0;
}

int tiered_bloom_check(tiered_bloom_t *tb, uint64_t nonce) {
    if (bf_check(&tb->tier1, nonce)) return 1;
    if (bf_check(&tb->tier2, nonce)) return 1;
    if (tb->tier3_active && bf_check(&tb->tier3, nonce)) return 1;
    return 0;
}

void tiered_bloom_insert(tiered_bloom_t *tb, uint64_t nonce) {
    bf_insert(&tb->tier1, nonce);
    bf_insert(&tb->tier2, nonce);
    if (tb->tier3_active) bf_insert(&tb->tier3, nonce);
    
    double fill = tiered_bloom_fill_pct(tb);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_sec = ts.tv_sec;
    
    if (!tb->degraded_mode && fill >= FILL_DEGRADED_PCT) {
        tb->degraded_mode = 1;
        tb->tier3_active = 1;
        tb->degraded_since_sec = now_sec;
        fprintf(stderr, "[S-IPv4 V2] DEGRADED_MODE activated — fill %.1f%%\n", fill);
    } else if (tb->degraded_mode && fill < 30.0) {
        if (now_sec - tb->degraded_since_sec >= 30) {
            tb->degraded_mode = 0;
            tb->tier3_active = 0;
            fprintf(stderr, "[S-IPv4 V2] DEGRADED_MODE cleared\n");
        }
    } else if (tb->degraded_mode && fill >= 30.0) {
        tb->degraded_since_sec = now_sec;
    }
}

uint32_t sipv4_adaptive_window_sec(double fill_pct) {
    if (fill_pct >= FILL_EMERGENCY_PCT) return 0;
    if (fill_pct >= FILL_HIGH_PCT) return WINDOW_HIGH_SEC;
    if (fill_pct >= FILL_ELEVATED_PCT) return WINDOW_ELEVATED_SEC;
    return WINDOW_NORMAL_SEC;
}

uint32_t sipv4_adaptive_rotation_sec(double fill_pct) {
    (void)fill_pct;
    return 5;
}

int replay_check_and_insert(tiered_bloom_t *tb, uint64_t nonce, uint64_t timestamp) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t mono_now = ts.tv_sec;
    
    double fill = tiered_bloom_fill_pct(tb);
    uint32_t aw = sipv4_adaptive_window_sec(fill);
    
    uint64_t diff = mono_now > timestamp ? (mono_now - timestamp) : (timestamp - mono_now);
    
    if (aw == 0) {
        if (diff > 0) return 1;
    } else {
        if (diff > aw) return 1;
    }
    
    if (tiered_bloom_check(tb, nonce)) return 1;
    tiered_bloom_insert(tb, nonce);
    return 0;
}

#ifdef SIPV4_TEST_MODE
void tiered_bloom_force_fill(tiered_bloom_t *tb, uint64_t count) {
    /* Directly set insert_count to simulate fill without inserting real nonces */
    tb->tier2.insert_count = count;
}
#endif

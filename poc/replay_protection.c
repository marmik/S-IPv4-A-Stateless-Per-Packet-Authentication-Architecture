/*
 * replay_protection.c — Dual-window rotating Bloom filter + timestamp check
 *
 * Rotation strategy:
 *   Every BLOOM_ROTATE_SEC seconds the "current" filter becomes "previous"
 *   and a fresh empty filter becomes "current".  A nonce is considered a
 *   replay if it appears in EITHER filter.  This mirrors the epoch-key
 *   overlap logic required by the S-IPv4 spec.
 *
 * Bloom filter sizing:
 *   m = -(n * ln(p)) / (ln(2)^2)    using BLOOM_CAPACITY and BLOOM_FP_RATE
 *   k = (m/n) * ln(2)
 */

#include "replay_protection.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* ── Portable htobe64 ───────────────────────────────────────────── */
#ifdef __APPLE__
#  include <libkern/OSByteOrder.h>
#  define htobe64_s(x)  OSSwapHostToBigInt64(x)
#else
#  include <endian.h>
#  define htobe64_s(x)  htobe64(x)
#endif

/* ══════════════════════════════════════════════════════════════════ */
/*  Hash functions for the Bloom filter                              */
/*                                                                   */
/*  We use a double-hashing scheme:                                  */
/*    h_i(x) = (h1(x) + i * h2(x)) mod m                           */
/*  where h1, h2 are two independent FNV-1a hashes.                 */
/*  This is more efficient than k independent hash calls.            */
/* ══════════════════════════════════════════════════════════════════ */

static uint64_t fnv1a_64(const uint8_t *data, size_t len, uint64_t seed)
{
    uint64_t h = 14695981039346656037ULL ^ seed;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Compute k bit positions via double hashing. */
static void bloom_positions(uint64_t nonce, uint64_t out[BLOOM_NUM_HASHES])
{
    uint64_t be = htobe64_s(nonce);
    uint8_t *bytes = (uint8_t *)&be;

    uint64_t h1 = fnv1a_64(bytes, 8, 0x1234567890ABCDEFULL);
    uint64_t h2 = fnv1a_64(bytes, 8, 0xFEDCBA0987654321ULL);

    /* Ensure h2 is odd so it's coprime to m, giving better distribution */
    h2 |= 1;

    for (int i = 0; i < BLOOM_NUM_HASHES; i++) {
        out[i] = (h1 + (uint64_t)i * h2) % BLOOM_SIZE_BITS;
    }
}

/* ── Bloom filter helpers ───────────────────────────────────────── */

static inline void bloom_set(bloom_filter_t *bf, uint64_t pos)
{
    bf->bits[pos / 8] |= (1u << (pos % 8));
}

static inline bool bloom_test(const bloom_filter_t *bf, uint64_t pos)
{
    return (bf->bits[pos / 8] & (1u << (pos % 8))) != 0;
}

static bool bloom_might_contain(const bloom_filter_t *bf, uint64_t nonce)
{
    uint64_t positions[BLOOM_NUM_HASHES];
    bloom_positions(nonce, positions);
    for (int i = 0; i < BLOOM_NUM_HASHES; i++) {
        if (!bloom_test(bf, positions[i])) return false;
    }
    return true;
}

static void bloom_insert(bloom_filter_t *bf, uint64_t nonce)
{
    uint64_t positions[BLOOM_NUM_HASHES];
    bloom_positions(nonce, positions);
    for (int i = 0; i < BLOOM_NUM_HASHES; i++) {
        bloom_set(bf, positions[i]);
    }
}

/* ── Bloom filter allocation ────────────────────────────────────── */

static void bloom_alloc(bloom_filter_t *bf)
{
    bf->bits = calloc(BLOOM_SIZE_BYTES, 1);
    if (!bf->bits) {
        perror("bloom_alloc");
        exit(1);
    }
}

static void bloom_free(bloom_filter_t *bf)
{
    free(bf->bits);
    bf->bits = NULL;
}

static void bloom_clear(bloom_filter_t *bf)
{
    memset(bf->bits, 0, BLOOM_SIZE_BYTES);
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Public API                                                       */
/* ══════════════════════════════════════════════════════════════════ */

void replay_init(replay_state_t *rs)
{
    bloom_alloc(&rs->current);
    bloom_alloc(&rs->previous);
    rs->last_rotation = time(NULL);

    /* Print sizing info for verification */
    fprintf(stderr,
        "[replay_init] Bloom filter sized for %d nonces at %.1f%% FP rate\n"
        "  m = %llu bits (%.2f KiB per filter, %.2f KiB dual-window)\n"
        "  k = %d hash functions\n",
        BLOOM_CAPACITY,
        BLOOM_FP_RATE * 100.0,
        (unsigned long long)BLOOM_SIZE_BITS,
        (double)BLOOM_SIZE_BYTES / 1024.0,
        (double)BLOOM_SIZE_BYTES * 2.0 / 1024.0,
        BLOOM_NUM_HASHES);
}

void replay_destroy(replay_state_t *rs)
{
    bloom_free(&rs->current);
    bloom_free(&rs->previous);
}

bool timestamp_valid(uint64_t pkt_timestamp)
{
    time_t now = time(NULL);
    int64_t diff = (int64_t)now - (int64_t)pkt_timestamp;
    if (diff < 0) diff = -diff;
    return diff <= S_IPV4_DELTA_SEC;
}

/* Rotate filters if enough time has passed. */
static void maybe_rotate(replay_state_t *rs)
{
    time_t now = time(NULL);
    if ((now - rs->last_rotation) >= BLOOM_ROTATE_SEC) {
        /* previous ← current,  current ← empty                    */
        /* Swap pointers instead of copying megabytes of data.      */
        uint8_t *tmp = rs->previous.bits;
        rs->previous.bits = rs->current.bits;
        rs->current.bits  = tmp;
        bloom_clear(&rs->current);
        rs->last_rotation = now;
    }
}

bool nonce_check_and_insert(replay_state_t *rs, uint64_t nonce)
{
    maybe_rotate(rs);

    /* Check both windows */
    if (bloom_might_contain(&rs->current,  nonce) ||
        bloom_might_contain(&rs->previous, nonce))
    {
        return false;   /* replay detected */
    }

    /* Fresh nonce — insert into current filter */
    bloom_insert(&rs->current, nonce);
    return true;
}

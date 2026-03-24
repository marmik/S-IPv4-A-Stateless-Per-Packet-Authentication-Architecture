/*
 * replay_protection.h — Timestamp window + dual-Bloom-filter replay guard
 *
 * Bloom filter sized from standard formula:
 *   m = -(n * ln(p)) / (ln(2)^2)
 *   k = (m/n) * ln(2)
 *
 * where n = BLOOM_CAPACITY (max nonces per window), p = target FP rate.
 */

#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include "s_ipv4.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* ── Bloom Filter Design Parameters ─────────────────────────────── */
/* Override at compile time: -DBLOOM_CAPACITY=5000000                */
#ifndef BLOOM_CAPACITY
#  define BLOOM_CAPACITY  2000000   /* max nonces per filter window  */
#endif

#ifndef BLOOM_FP_RATE
#  define BLOOM_FP_RATE   0.001     /* target false-positive rate    */
#endif

/*
 * Derived constants (computed from the formulas):
 *
 *   m = -(n * ln(p)) / (ln(2)^2)
 *     = -(2000000 * ln(0.001)) / (0.693147^2)
 *     = -(2000000 * (-6.907755)) / 0.480453
 *     = 13815510.56 / 0.480453
 *     ≈ 28755175 bits
 *     ≈ 3594397 bytes
 *     → round up to 3604480 bytes (3520 KiB, aligned to 4096)
 *
 *   k = (m/n) * ln(2) = (28755175 / 2000000) * 0.693147 ≈ 9.97 → 10
 *
 * For compile-time derivation we use conservative rounded values:
 *   m_bytes = 3604480  (3520 KiB = 3.4375 MiB per filter)
 *   k       = 10
 */

/* Sizing: ~3.44 MiB per filter, 6.88 MiB dual-window total.       */
/* This gives FP < 0.1% for up to 2 million nonces per window.     */
#define BLOOM_SIZE_BYTES  3604480
#define BLOOM_SIZE_BITS   ((uint64_t)BLOOM_SIZE_BYTES * 8)
#define BLOOM_NUM_HASHES  10

/* Rotation interval matches S_IPV4_DELTA_SEC so the two filters    */
/* together cover the full acceptance window.                       */
#define BLOOM_ROTATE_SEC  S_IPV4_DELTA_SEC

/*
 * The filter is heap-allocated because 3.4 MiB per filter is too
 * large for the stack.  Use replay_init() / replay_destroy().
 */
typedef struct {
    uint8_t *bits;   /* heap-allocated, BLOOM_SIZE_BYTES            */
} bloom_filter_t;

/* ── Replay Engine State ────────────────────────────────────────── */
typedef struct {
    bloom_filter_t  current;
    bloom_filter_t  previous;
    time_t          last_rotation;   /* wall time of last rotate     */
} replay_state_t;

/* Initialise the replay engine (allocates + zeroes both filters).  */
/* Prints computed m, k, and memory to stderr for verification.     */
void replay_init(replay_state_t *rs);

/* Free heap memory used by the Bloom filters. */
void replay_destroy(replay_state_t *rs);

/* Check timestamp window: |now - pkt_ts| ≤ Δ.                     */
/* Returns true if timestamp is within the acceptable window.       */
bool timestamp_valid(uint64_t pkt_timestamp);

/* Check + insert a nonce into the dual Bloom filter.               */
/* Returns true if the nonce is fresh (not a replay).               */
/* Automatically rotates the filter if BLOOM_ROTATE_SEC elapsed.    */
bool nonce_check_and_insert(replay_state_t *rs, uint64_t nonce);

#endif /* REPLAY_PROTECTION_H */

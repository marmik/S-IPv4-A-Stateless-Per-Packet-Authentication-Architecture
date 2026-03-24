# S-IPv4 Changelog

All notable changes to this project are documented in this file.
Entries follow the format: `[Version] — Date — Category — Description`.

---

## [V2.0] — 2025 — Major Protocol Upgrade (IEEE Expert Review Aligned)

### Protocol — Header Versioning
- **Added** explicit 1-byte `s_flag` version encoding: `bits [7:4]` = magic nibble `0x9`; `bits [3:0]` = version nibble. V2 flag = `0x95`.
- **Rationale:** V1 used a fixed magic byte (`0x94`) with no version discriminator, making future header evolution impossible without a full flag reassignment. V2 receivers can simultaneously support both V1 (`0x94`) and V2 (`0x95`) packets, enabling a backward-compatible migration path.

### Protocol — Header Extension (`key_ver` Field)
- **Added** `key_ver` (2-byte unsigned integer) to the S-IPv4 header. V2 full header is now **43 bytes** (V1 was 41 bytes).
- **Layout:** `s_flag (1) | node_id (8) | timestamp (8) | nonce (8) | key_ver (2) | hmac (16)`
- **Rationale:** Without a key version indicator in-wire, receivers during key rotation had no way to distinguish packets signed with the current key from those signed with the next key. `key_ver` enables live key rotation with zero traffic disruption.

### Security — Epoch Key Lifecycle (Previously Undefined)
- **Defined** full key lifecycle: 256-bit HMAC-SHA256 keys, 24-hour epoch duration (configurable), derived via `HKDF-SHA256(master_secret, epoch_counter || node_label)`.
- **Defined** key rotation overlap window: receiver accepts packets from either `epoch_N` or `epoch_N+1` during a 60-second pre-boundary window, and from either `epoch_N` or `epoch_N-1` during a 60-second post-boundary grace period.
- **Defined** three supported key distribution channels: manual provisioning, encrypted HTTPS config push, and (stretch goal) ECDH Curve25519 one-time bootstrap exchange.
- **Rationale:** V1 described Epoch Keys as "pre-shared symmetric keys" without specifying key length, epoch duration, rotation mechanism, or grace period. This was a fundamental protocol specification gap identified by IEEE reviewers.

### Security — Deterministic node_id Derivation
- **Changed** `node_id` derivation from manual assignment to key-derived: `node_id = HMAC-SHA256(epoch_key, "node_id_v2")[0:8]`.
- **Effect:** node_id is unique by construction (collision probability ~3×10⁻¹⁹ for 8 bytes). node_id rotates automatically with each Epoch Key rotation, providing identity freshness and limiting long-term tracking.
- **Rationale:** V1 used manually assigned node_ids with no allocation authority, creating a namespace collision risk in any deployment beyond a single managed segment.

### Security — Monotonic Clock Anchoring (NTP Spoof Resistance)
- **Changed** timestamp window enforcement from `CLOCK_REALTIME` to `CLOCK_MONOTONIC` anchored at startup.
- **Added** explicit NTP drift compensation term: `valid_window = base_window ± ntp_drift_bound` (default `±0.5 seconds`).
- **Rationale:** `CLOCK_REALTIME` is adjustable by NTP. An attacker controlling NTP could widen the effective replay window. `CLOCK_MONOTONIC` is unspoofable from the network. This addresses the clock synchronization attack class identified in the IEEE review.

### Security — Three-Tier Adaptive Bloom Filter (Saturation Resistance)
- **Replaced** V1 single dual-window Bloom filter with a three-tier cascade:
  - Tier 1 — Fast Filter: 50,000 nonces, ~350 KiB, L1 cache-resident hot path.
  - Tier 2 — Primary Filter: 2,000,000 nonces, ~7,040 KiB, normal operation (matches V1 capacity).
  - Tier 3 — Overflow Filter: 10,000,000 nonces, ~35 MiB, activated only under flood (`DEGRADED_MODE`).
- **Added** dynamic timestamp window tightening on fill thresholds: 5s (normal) → 3s (20–50% fill) → 1s (50–75%) → 0.5s (>75%).
- **Added** adaptive rotation acceleration: rotate every 5s (normal) → 2.5s (30–60% fill) → 1s (>60% fill).
- **Added** `DEGRADED_MODE` automatic trigger at Tier 2 fill > 80%: activates Tier 3, tightens window to 0.5s, emits high-priority syslog alert.
- **Rationale:** V1's fixed-capacity filter had a "sharp memory cliff" — saturation caused FP rate to approach 100%, blocking all legitimate traffic. The adaptive system gracefully degrades instead.

### Protocol — Fragmentation Elimination (Statelessness Preservation)
- **Added** mandatory `IP_DONTFRAG` socket enforcement on all V2 senders (`IP_DONTFRAG` on macOS/BSD; `IP_MTU_DISCOVER / IP_PMTUDISC_DO` on Linux).
- **Added** compile-time `MAX_SIPV4_PAYLOAD` constant: `1431 bytes` (`1500 - 20 (IP) - 8 (UDP) - 41 (S-IPv4 header) = 1431`).
- **Added** 1431-byte MTU guard enforced at send path.
- **Rationale:** IP fragmentation at intermediate routers forces the receiver's stack to buffer reassembly state, directly contradicting S-IPv4's stateless design goal. This was acknowledged in V1 §VI but not addressed architecturally.

### Cryptography — OpenSSL 3.0 EVP_MAC Migration
- **Removed** all V1 OpenSSL deprecated API hooks (`HMAC_CTX_new`, `HMAC_Init_ex`, `HMAC_Update`, `HMAC_Final`, `HMAC_CTX_free`).
- **Replaced** with OpenSSL 3.0 `EVP_MAC` primitives throughout `poc_v2/crypto_core.c`.
- **Result:** `poc_v2/` builds with zero warnings on OpenSSL 3.0.
- **Note:** `poc_v2/bench/bench_crypto.c` retains V1 `HMAC_CTX` references (standalone benchmark utility not yet migrated). This is a known cosmetic discrepancy — core protocol binaries (`client`, `server`) are fully clean.
- **Rationale:** OpenSSL 3.0 deprecates the legacy `HMAC_*` API family. V2 targets production-grade cryptographic hygiene.

### Testing — V2 Test Suite Extension
- **Added** 5 V2-exclusive test phases to the verification suite (15 total: 10 V1 + 5 V2):
  - Version flag corruption detection (`s_flag != 0x95` rejection)
  - Deterministic node_id distribution tracking
  - Deterministic `key_ver` persistence guarantees
  - Absolute MTU enforcement validation
  - `DEGRADED_MODE` Bloom filter threshold triggering
- **Added** `SIPV4_TEST_MODE` compile-time guard (`#ifdef SIPV4_TEST_MODE`) isolating `tiered_bloom_force_fill` from production builds.

### Build — Makefile
- **Updated** Makefile to link against OpenSSL 3.0 `EVP_MAC` cleanly with zero compiler warnings.
- **Verified** clean build on macOS (Apple M2 Pro, Homebrew OpenSSL 3.x) and Linux (Ubuntu 22.04 LTS) target environments.

---

## [V1.0] — 2024 — Initial Proof-of-Concept (Loopback Validated)

### Core Protocol
- Stateless per-packet HMAC-SHA256 authentication shim over UDP encapsulation.
- 41-byte header: `s_flag (1) | node_id (8) | timestamp (8) | nonce (8) | hmac (16)`.
- Magic byte `0x94` for fast early-exit on non-S-IPv4 traffic.
- 64-bit atomic counter nonce (upgraded from 32-bit to eliminate space exhaustion under heavy load).
- Big-endian HMAC serialization (correctness fix from prototype).
- SHA256(payload) → concatenate timestamp + nonce → HMAC sign (hash-then-MAC pattern, prevents length extension attacks).
- Constant-time token comparison via `CRYPTO_memcmp` (timing attack mitigation).

### Replay Protection
- Dual-window Bloom filter: 2,000,000 nonce capacity, ~7,040 KiB, 0.000467% FP rate at 1M nonces.
- 5-second timestamp acceptance window.

### Operational Modes
- `ENFORCE` mode: invalid packets are dropped.
- `AUDIT` mode: invalid packets are logged, payload delivery behavior observable without dropping.

### Performance (Single Machine, macOS Loopback, Apple M2 Pro)
- Token generation latency: P50 = 0 µs, P95 = 1 µs, P99 = 1 µs (1 µs macOS clock resolution limit).
- Throughput overhead: 7.4% at 10k pps → 18.4% at 1M pps (scaling anomaly under investigation).
- Peak verified throughput: ~387k pps on loopback.
- Bloom filter FP rate confirmed at 0.000467% at 1M nonces.

### Known Limitations (Carried into V2)
- Loopback-only evaluation; no real-network or multi-machine benchmarks.
- Epoch Key lifecycle (duration, rotation, distribution) left undefined.
- `node_id` namespace globally uncoordinated; collision possible in large deployments.
- IP fragmentation forces receiver reassembly state, contradicting stateless design.
- Timestamp window uses `CLOCK_REALTIME` — vulnerable to NTP manipulation.
- No protocol version field in header.
- OpenSSL deprecated `HMAC_*` API in use (generates compiler warnings on OpenSSL 3.0).

---

*This changelog covers the S-IPv4 research proof-of-concept codebase. V1 is frozen. V2 is the active development branch. See `S-IPv4-Architecture.md` and `03_S-IPv4_V2_Upgrade_Design.md` for full architectural rationale.*

# S-IPv4 Version 2 — Upgrade Design Specification
**Document Type:** Protocol Evolution Reference
**Scope:** Architectural upgrades addressing all V1 limitations identified from review, implementation experience, and design discussion
**Status:** Design Proposal — Pre-Implementation

---

## OVERVIEW

S-IPv4 Version 1 was a proof-of-concept stateless per-packet authentication shim validated on a single-machine macOS loopback environment. V1 proved the core thesis: HMAC-SHA256 based packet origin authentication is computationally feasible at commodity hardware speeds (0.180 µs token generation, 18.4% throughput overhead).

Version 2 addresses the following problem classes:

| Problem | Category | V1 Status | V2 Target |
|---|---|---|---|
| Transit bandwidth consumption by spoofed traffic | Architectural | Unsolved | Partially mitigated |
| Bloom filter saturation under flood | Protocol | Acknowledged | Solved |
| Packet fragmentation breaks statelessness | Protocol | Acknowledged | Solved |
| UDP encapsulation overhead for small payloads | Engineering | Known | Mitigated |
| node_id namespace collision | Protocol | Acknowledged | Solved |
| Epoch Key bootstrapping and rotation | Protocol | Undefined | Defined |
| Clock synchronization dependency | Security | Unaddressed | Addressed |
| No protocol versioning | Protocol | Missing | Added |
| Cryptographic agility | Security | Absent | Scaffolded |

---

## PROBLEM 1 — TRANSIT BANDWIDTH CONSUMPTION

### V1 Status
S-IPv4 V1 drops invalid packets at the destination endpoint. Spoofed packets with valid-looking timestamps still consume transit bandwidth across the entire network path from the spoofed source to the destination. The protocol has no upstream presence to stop this.

### V2 Design: Source-Side Rate Limiting + Epoch Key Revocation Signal

#### 1.1 — Sender-Side Epoch-Scoped Rate Limiter
Each S-IPv4 sender implementation enforces a configurable per-epoch outbound packet rate limit. Even if a node is compromised, the attacker cannot emit more than `MAX_PPS_PER_EPOCH` packets per second without triggering the local rate limiter.

```
SENDER_RATE_LIMIT {
    max_pps_per_epoch: configurable (default: 100,000 pps)
    enforcement: token bucket per node_id
    overflow_behavior: DROP_LOCAL (never transmit excess)
}
```

**Why this helps:** A compromised sender with a valid Epoch Key is the worst-case attack scenario for S-IPv4. Rate limiting at the sender caps the blast radius. Even 100k pps from one node is manageable if the receiver can reject them early.

**Limitation:** This only works if the sender's S-IPv4 implementation is honest. A fully compromised or custom sender implementation ignores this. This upgrade cannot solve the fundamental physics problem: stopping transit bandwidth requires upstream cooperation.

#### 1.2 — Lightweight node_id Rejection Signal
When the receiver's Bloom filter is approaching saturation or a node_id is generating anomalously high traffic, the receiver broadcasts a lightweight "REJECT node_id" signal packet back to the sender's observed source address. The packet is:

```
REJECTION_SIGNAL_HEADER {
    s_flag:        0x94 (same magic byte)
    msg_type:      0x02 (REJECT_NODE signal)
    node_id:       [8 bytes — the rejected node]
    epoch_hmac:    [16 bytes — signed with receiver's own key to prevent spoofed rejections]
    reason_code:   1 byte (FLOOD / SATURATION / BAD_HMAC / EXPIRED_KEY)
}
```

A cooperating upstream router or middlebox that implements a simple "S-IPv4 rejection relay" can optionally honor this signal and install a temporary ACL or rate limit for that source. This does not require routers to be S-IPv4 aware — it is opt-in cooperation.

**Honest assessment:** Problem 1 cannot be fully solved at the endpoint alone. The physics require upstream cooperation. V2 provides the tooling for that cooperation without mandating it. This is the best achievable outcome within S-IPv4's design constraints.

---

## PROBLEM 2 — BLOOM FILTER SATURATION UNDER FLOOD

### V1 Status
The V1 dual-window Bloom filter has a fixed capacity of 2M nonces. If an attacker floods the receiver with millions of valid-timestamp, valid-HMAC, unique-nonce packets (which requires a compromised Epoch Key), the filter saturates and the FP rate approaches 100%, blocking all legitimate traffic. The "sharp memory cliff" is acknowledged but unaddressed.

### V2 Design: Three-Tier Adaptive Bloom Filter System

#### 2.1 — Dynamic Window Tightening
The timestamp acceptance window shrinks automatically when filter fill exceeds configurable thresholds:

```
ADAPTIVE_WINDOW_POLICY {
    fill < 20%:   window = 5 seconds (normal)
    fill 20–50%:  window = 3 seconds (elevated)
    fill 50–75%:  window = 1 second  (high alert)
    fill > 75%:   window = 0.5 seconds (emergency)
}
```

**Effect:** Tighter window dramatically reduces the valid nonce space. An attacker must generate and transmit unique valid nonces faster to maintain saturation. At 0.5 second windows, the attacker must flood at the exact moment they replay — practically infeasible without precise timing control.

#### 2.2 — Adaptive Rotation Speed
The Bloom filter window rotation (which flushes old nonces) accelerates proportionally to filter fill:

```
ROTATION_POLICY {
    fill < 30%:  rotate every 5 seconds (normal cadence)
    fill 30–60%: rotate every 2.5 seconds (2x acceleration)
    fill > 60%:  rotate every 1 second (aggressive flush)
}
```

**Effect:** Faster rotation means old nonces are evicted sooner, freeing filter capacity. The tradeoff is that nonces evicted before their timestamp window expires could theoretically be replayed. This is acceptable because: (a) replay within the shortened emergency window is much harder, and (b) the protocol already operates probabilistically under attack.

#### 2.3 — Tiered Three-Level Bloom Filter
Replace V1's single dual-window filter with a three-tier cascade:

```
TIER 1 — Fast Filter (small, L1 cache-resident)
    capacity:   50,000 nonces
    memory:     ~350 KiB
    purpose:    Absorb burst traffic, O(1) hot-path lookup

TIER 2 — Primary Filter (current V1 filter)
    capacity:   2,000,000 nonces
    memory:     7,040 KiB
    purpose:    Normal operation replay protection

TIER 3 — Overflow Filter (large, slower)
    capacity:   10,000,000 nonces
    memory:     ~35 MiB
    purpose:    Saturation-resistant extended protection, activated only under flood
```

**Lookup path:** Check Tier 1 first → on miss, check Tier 2 → on Tier 2 saturation signal, activate Tier 3. Saturation hits Tier 1 first (cheap to flush), then Tier 2, before reaching Tier 3. This distributes the saturation pressure and buys time for the adaptive rotation to take effect.

#### 2.4 — Saturation Alert and Graceful Degradation Mode
When Tier 2 fill exceeds 80%, the receiver enters **DEGRADED_MODE**:
- Logs a high-priority alert (syslog / SNMP trap)
- Activates Tier 3 filter
- Tightens timestamp window to 0.5 seconds
- Optionally activates AUDIT mode instead of ENFORCE to prevent legitimate traffic blackout while the flood is investigated

**Transition back to normal:** When fill drops below 30% for 30 consecutive seconds, revert to normal window and rotation speed.

---

## PROBLEM 3 — PACKET FRAGMENTATION BREAKING STATELESSNESS

### V1 Status
If a datagram exceeds path MTU, IP fragmentation occurs. The receiver's IP stack must buffer fragments and reassemble before S-IPv4 can verify the HMAC over the complete payload. This forces temporary state buffering, contradicting the stateless design.

### V2 Design: Mandatory Path MTU Enforcement

#### 3.1 — IP_DONTFRAG as Protocol Requirement
V2 mandates that all S-IPv4 senders set the `IP_DONTFRAG` socket option (or `IP_MTU_DISCOVER` with `IP_PMTUDISC_DO` on Linux). This prevents IP fragmentation at the sender's socket level.

```
SENDER_SOCKET_INIT {
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)  // Linux
    setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, 1)                   // macOS/BSD
}
```

**Effect:** If the packet exceeds path MTU, the sender receives an ICMP "Fragmentation Needed" message and must reduce payload size before retransmitting. This keeps S-IPv4 stateless at the receiver — no fragmentation means no reassembly state.

#### 3.2 — Maximum Payload Size Enforcement
V2 introduces a `MAX_SIPV4_PAYLOAD` constant defined as `min(1500 - 20 - 8 - 41) = 1431 bytes` (Ethernet MTU - IP header - UDP header - S-IPv4 header). The sender must not exceed this without explicit negotiation.

#### 3.3 — Application-Layer Segmentation Shim
For applications that need to send data larger than `MAX_SIPV4_PAYLOAD`, V2 provides an optional application-layer segmentation feature:
- Large messages are split into segments before S-IPv4 header addition
- Each segment gets its own S-IPv4 header (with incremented nonce)
- A segment index field (2 bytes) is added to the S-IPv4 header for reassembly hint
- Reassembly is the application's responsibility, not S-IPv4's

**Result:** Statelessness is preserved at the S-IPv4 layer. The application layer handles reassembly above the shim.

---

## PROBLEM 4 — UDP ENCAPSULATION OVERHEAD FOR SMALL PAYLOADS

### V1 Status
The fixed 41-byte S-IPv4 header adds 32% overhead on a 128-byte payload. For IoT-style small message applications this is significant.

### V2 Design: Compact Header Mode

#### 4.1 — Compact Mode Header (21 bytes)
A compact header mode is defined for trusted environments (e.g., within a single enterprise subnet) where the full 8-byte node_id and 8-byte timestamp can be abbreviated:

```
COMPACT_SIPV4_HEADER (21 bytes) {
    s_flag:     1 byte  (0x95 — compact mode magic, distinct from 0x94)
    node_id:    4 bytes (truncated — acceptable within known-small node spaces)
    nonce:      4 bytes (32-bit counter — acceptable for short-session traffic)
    hmac:       12 bytes (truncated HMAC-96 — IETF-standard truncation per RFC 2404)
}
```

**Trade-offs:**
- 32-bit nonce: suitable for sessions with < 4 billion packets (adequate for most IoT use cases)
- 96-bit HMAC: still provides 48-bit collision resistance — adequate for non-high-value traffic
- Reduces overhead on 128-byte payload from 32% to ~16%

**Security note:** Compact mode is explicitly NOT recommended for high-security or high-volume environments. It is a deployment flexibility option for constrained devices.

---

## PROBLEM 5 — node_id NAMESPACE COLLISION

### V1 Status
The 8-byte node_id has no allocation authority, permitting two valid nodes to share the same ID. In V1's pre-shared key model this is particularly problematic — two nodes sharing a node_id must share an Epoch Key, which means neither can authenticate exclusively.

### V2 Design: Deterministic node_id Derivation

#### 5.1 — Key-Derived node_id
Instead of manually assigned node_ids, V2 derives the node_id deterministically from the Epoch Key itself:

```
node_id = HMAC-SHA256(epoch_key, "node_id_v2")[0:8]
```

**Effect:** Since each node has a unique Epoch Key, each node has a unique node_id (with birthday-bound collision probability of ~3×10⁻¹⁹ for 8 bytes — negligible). Collision is now cryptographically impossible unless two nodes share an Epoch Key, which means they are intentionally the same trust principal anyway.

#### 5.2 — node_id Change on Key Rotation
When the Epoch Key rotates, the node_id derived from it also changes. This provides automatic identity freshness and limits the impact of long-term node_id tracking by an adversary.

---

## PROBLEM 6 — EPOCH KEY BOOTSTRAPPING AND ROTATION (V1 UNDEFINED)

### V1 Status
The Epoch Key concept is central to S-IPv4 but completely undefined in V1. The paper mentions "pre-shared symmetric keys" without specifying: key length, epoch duration, rotation mechanism, or distribution channel.

### V2 Design: Defined Key Lifecycle

#### 6.1 — Key Specification
```
EPOCH_KEY_SPEC {
    algorithm:   HMAC-SHA256
    key_length:  256 bits (32 bytes)
    epoch_duration: configurable (default: 24 hours)
    derivation:  HKDF-SHA256(master_secret, epoch_counter || node_label)
}
```

#### 6.2 — Key Rotation Protocol
Epoch Key rotation uses a pre-derived key ladder:

```
KEY_ROTATION {
    current_key = HKDF(master_secret, epoch_N)
    next_key    = HKDF(master_secret, epoch_N+1)
    
    overlap_window: 60 seconds before epoch boundary,
                    receiver accepts packets signed by EITHER current or next key
    
    grace_period:   60 seconds after epoch boundary,
                    receiver accepts packets signed by EITHER current or previous key
}
```

**Effect:** During key rotation, no traffic disruption occurs. The 2-minute grace window (60s before + 60s after) handles network jitter and clock skew.

#### 6.3 — Key Distribution Channels (Out-of-Band)
V2 explicitly documents three supported distribution channels:
1. **Manual provisioning** — pre-loaded at device deployment (enterprise managed devices)
2. **Encrypted configuration push** — via HTTPS management plane (cloud-managed)
3. **ECDH one-time bootstrap exchange** — using Curve25519 for initial key establishment, then the established symmetric key seeds the HKDF ladder

Channel 3 is the V2 stretch goal. It eliminates the fully out-of-band requirement for new node onboarding without adding PKI dependency (ECDH exchange uses ephemeral keys, no certificates required).

---

## PROBLEM 7 — CLOCK SYNCHRONIZATION DEPENDENCY

### V1 Status
The 5-second timestamp window assumes synchronized clocks. NTP spoofing could allow an attacker to shift the receiver's clock, widening the effective replay window. This is unaddressed in V1.

### V2 Design: Monotonic Clock Anchoring + NTP Drift Bound

#### 7.1 — Local Monotonic Clock for Window Enforcement
The receiver's timestamp comparison uses `CLOCK_MONOTONIC` (not `CLOCK_REALTIME`) anchored at startup. Absolute timestamps from senders are validated against a locally-maintained monotonic offset, not the live system wall clock.

**Effect:** NTP adjustments to the system wall clock do not directly affect the replay window. The monotonic clock cannot be spoofed remotely.

#### 7.2 — Drift-Adaptive Window
The timestamp window includes an explicit NTP drift compensation term:

```
valid_window = base_window ± ntp_drift_bound
    base_window:     5 seconds
    ntp_drift_bound: 0.5 seconds (tunable — based on NTP stratum quality)
    effective_window: 4.5 – 5.5 seconds
```

**Effect:** Tight drift bounding limits NTP manipulation impact. A 0.5-second drift allowance is conservative for well-managed networks (NTP typical drift < 50ms) and the full window is only exploitable if NTP itself is compromised.

---

## PROBLEM 8 — PROTOCOL VERSION FIELD (V1 MISSING)

### V2 Header Design: Versioned Header

V2 redefines the `s_flag` byte to encode both the magic identifier and the version:

```
s_flag byte encoding:
    bits [7:4]:  magic nibble = 0x9 (fixed — identifies S-IPv4 protocol family)
    bits [3:0]:  version nibble = 0x1 (V1), 0x2 (V2), etc.
    
    V1 s_flag = 0x94  →  magic=0x9, version=4 (retroactively = V1.x)
    V2 s_flag = 0x95  →  magic=0x9, version=5 (V2.0)
    Compact s_flag = 0x96 → magic=0x9, version=6 (V2 compact mode)
```

**Effect:** Receivers can simultaneously support V1 and V2 packets. Migration is backward compatible. Deprecation of V1 can be managed operationally.

---

## UPDATED V2 HEADER STRUCTURE

```
S-IPv4 V2 Full Header (43 bytes):
+-------+----------+-----------+-------+----------+--------+
| s_flag| node_id  | timestamp | nonce | key_ver  | hmac   |
| 1 byte| 8 bytes  | 8 bytes   | 8 bytes| 2 bytes | 16 bytes|
+-------+----------+-----------+-------+----------+--------+

New fields vs V1:
    key_ver (2 bytes): Epoch Key version counter — enables key rotation without traffic disruption
    
Removed fields vs V1:
    None — fully backward compatible at field level (key_ver is additive, total 43 bytes)
```

---

## V2 FEATURE ROADMAP SUMMARY

| Feature | Priority | Complexity | Impact |
|---|---|---|---|
| Adaptive Bloom filter (tightening + rotation) | P0 | Medium | High — solves saturation cliff |
| IP_DONTFRAG enforcement | P0 | Low | High — eliminates fragmentation state |
| Key-derived node_id | P0 | Low | Medium — eliminates collision risk |
| Epoch Key lifecycle definition | P0 | Medium | Critical — V1 is incomplete without this |
| Protocol version field in header | P0 | Low | Medium — enables future evolution |
| Tiered three-level Bloom filter | P1 | High | High — saturation resistance |
| key_ver field in header | P1 | Low | High — enables live key rotation |
| Compact header mode (21 bytes) | P1 | Medium | Medium — IoT/constrained devices |
| Rejection signal packet | P2 | Medium | Medium — optional upstream cooperation |
| Monotonic clock anchoring | P2 | Low | Medium — NTP attack resistance |
| ECDH one-time bootstrap | P3 | High | High — removes fully out-of-band key req. |
| Cryptographic agility scaffold | P3 | Medium | Low (current) / High (long-term) |

---

## V2 SECURITY ANALYSIS DELTA

| Property | V1 | V2 |
|---|---|---|
| Replay resistance under flood | Vulnerable to saturation | Adaptive window + tiered filter provides graceful degradation |
| Key rotation | Undefined / traffic disruption | Defined overlap window, key_ver field |
| node_id collision | Possible | Eliminated via key-derived ID |
| Fragmentation state | Forces implicit state | Eliminated via IP_DONTFRAG |
| NTP spoofing | Unaddressed | Mitigated via monotonic clock anchoring |
| Epoch Key bootstrap | Out-of-band only | V2 defines channels; V2 stretch: ECDH bootstrap |

---

*V2 design is informed by V1 implementation experience, peer review feedback, and protocol engineering best practices. All changes are designed to maintain backward compatibility at the magic byte level.*

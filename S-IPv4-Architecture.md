# S-IPv4: Stateless Per-Packet Network-Layer Trust Architecture

## 1. Design Goals

S-IPv4 introduces stateless, per-packet cryptographic legitimacy verification at the network layer while:

- Keeping IPv4 unchanged
- Preserving router forwarding speed
- Surviving NAT translation
- Tolerating packet loss and reordering
- Remaining incrementally deployable
- Operating independently from transport encryption (e.g., QUIC)

---

# 2. Layer Placement

## Classic TCP/IP Stack

```
Application
Transport (TCP / UDP)
Internet (IPv4)
Link Layer
```

## S-IPv4 Enhanced Stack

```
Application
Transport (TCP / UDP)
S-IPv4 (Trust & Identity Layer)

IPv4 (Unmodified)
Link Layer
```

S-IPv4 operates as a shim layer between Transport and IPv4.

---

# 3. High-Level Architecture

```
+--------------------------------------------------+
| Application Layer |
+--------------------------------------------------+
| Transport (TCP/UDP) |
| (QUIC optional) |
+--------------------------------------------------+
| S-IPv4 Layer |
| • Node Identity Binding |
| • Stateless Token Generation |
| • Timestamp Validation |
| • Replay Mitigation (Probabilistic) |
| • Packet Legitimacy Decision Engine |
+--------------------------------------------------+
| IPv4 (Unchanged) |
+--------------------------------------------------+
| Link Layer |
+--------------------------------------------------+
```

---

# 4. Packet Structure

## Full Packet Layout

```
[ IPv4 Header ]
[ UDP Header ] (QUIC transport)
[ S-IPv4 Mini Header ]
[ QUIC Encrypted Payload ]
```

IPv4 header is NOT modified.

---

## 4.1 S-IPv4 Mini Header Format

| S-Flag (1 byte) |
| NodeID Reference (4–8 bytes) |
| Timestamp (32-bit coarse time) |
| Nonce (32–64 bits random) |
| HMAC Token (128-bit truncated) |

Total overhead: ~32–40 bytes per packet.

---

# 5. Sender-Side Workflow

| Step | Operation                                      |
| ---- | ---------------------------------------------- | --- | ----- | --- | -------------- |
| 1    | Application generates data                     |
| 2    | QUIC encrypts payload                          |
| 3    | Compute `payload_hash = HASH(QUIC_ciphertext)` |
| 4    | Generate `token = HMAC(epoch_key, timestamp    |     | nonce |     | payload_hash)` |
| 5    | Attach S-IPv4 header                           |
| 6    | Send via IPv4 normally                         |

No per-flow state required.

---

# 6. Receiver-Side Workflow

| Step | Operation                                 |
| ---- | ----------------------------------------- |
| 1    | Receive IPv4 packet                       |
| 2    | Extract S-IPv4 header                     |
| 3    | Resolve `epoch_key` via NodeID            |
| 4    | Recompute HMAC                            |
| 5    | Verify token equality                     |
| 6    | Validate timestamp within window Δ        |
| 7    | Optional: Check nonce in Bloom filter     |
| 8    | Accept or Drop packet                     |
| 9    | If accepted → pass to QUIC for decryption |

All verification is per-packet and stateless.

---

# 7. Handling Real-World Network Conditions

## 7.1 Packet Loss

- Each packet independently verifiable
- No sequence chaining
- Loss does not affect future packet validation

## 7.2 Packet Reordering

- No dependency on sequence number
- Timestamp window validation only
- Reordering tolerated naturally

## 7.3 NAT IP Changes

- Identity not bound to IP address
- S-IPv4 header stored inside payload
- NAT rewriting does not affect token validity

## 7.4 Replay Mitigation

Replay bounded by:

```
| current_time - packet_timestamp | ≤ Δ
```

Optional probabilistic nonce tracking using Bloom filter.

---

# 8. Stateless Design Properties

| Property                     | Supported | Explanation                       |
| ---------------------------- | --------- | --------------------------------- |
| Packet loss tolerance        | Yes       | Independent token verification    |
| Packet reordering tolerance  | Yes       | No sequence dependency            |
| NAT compatibility            | Yes       | Identity independent of IP        |
| Router modification required | No        | Routers ignore S-IPv4             |
| Per-flow state required      | No        | Stateless per-packet verification |
| Replay fully eliminated      | No        | Time-bounded mitigation           |
| Flow continuity proof        | No        | Not chain-based                   |

---

# 9. Security Model

S-IPv4 ensures:

- Source authenticity (cryptographic)
- Packet integrity
- Stateless legitimacy enforcement
- Resistance to IP spoofing

S-IPv4 does NOT provide:

- Transport reliability
- Perfect replay prevention
- Traffic confidentiality (handled by QUIC)

---

# 10. Comparison with Existing Technologies

| Feature                 | TLS     | VPN     | IPsec     | S-IPv4 |
| ----------------------- | ------- | ------- | --------- | ------ |
| Network-layer trust     | No      | No      | Partial   | Yes    |
| Stateless per-packet    | No      | No      | No        | Yes    |
| NAT friendly            | Partial | Partial | Weak      | Yes    |
| Router changes required | No      | No      | Sometimes | No     |
| Stops spoofed packets   | No      | No      | Partial   | Yes    |

---

# 11. Core Principle

S-IPv4 separates:

- Routing (IPv4)
- Transport security (QUIC)
- Packet legitimacy (S-IPv4)

It transforms IPv4 from a trust-blind routing protocol into a trust-aware communication architecture without modifying the IPv4 header.

---

# 12. Design Philosophy

- Keep core network simple
- Push cryptographic verification to edges
- Maintain backward compatibility
- Allow incremental adoption
- Preserve Internet performance characteristics

---

# 13. System Deployment Architecture

## 13.1 End-Host Deployment Model

S-IPv4 is deployed at network endpoints only. The Internet core remains unchanged:

**Client Host**

```
┌─────────────────────────┐
│  Application Layer      │
├─────────────────────────┤
│  S-IPv4 Module          │
│  (Kernel/User-space)    │
├─────────────────────────┤
│  QUIC Transport         │
├─────────────────────────┤
│  IPv4 Stack             │
├─────────────────────────┤
│  Link Layer             │
└─────────────────────────┘
```

**Server Host**

```
┌─────────────────────────┐
│  Application Layer      │
├─────────────────────────┤
│  S-IPv4 Verifier        │
│  (Verification Engine)  │
├─────────────────────────┤
│  QUIC Transport         │
├─────────────────────────┤
│  IPv4 Stack             │
├─────────────────────────┤
│  Link Layer             │
└─────────────────────────┘
```

## 13.2 Full System Architecture

```
+------------------+        +------------------+        +------------------+
|     CLIENT       |        |    INTERNET      |        |     SERVER       |
|------------------|        |------------------|        |------------------|
| Application      |        |   Routers        |        | Application      |
| QUIC Layer       |        | (No changes)     |        | QUIC Layer       |
| S-IPv4 Module    | -----> | IPv4 Forwarding  | -----> | S-IPv4 Verifier  |
| IPv4 Stack       |        | Only             |        | IPv4 Stack       |
| Link Layer       |        |                  |        | Link Layer       |
+------------------+        +------------------+        +------------------+

Legend:
← S-IPv4 packets flow through Internet without modification
← Routers see standard IPv4, forward normally
← S-IPv4 verification happens only at endpoints
```

## 13.3 Deployment Characteristics

| Property                 | Details                                       |
| ------------------------ | --------------------------------------------- |
| **Scope**                | End-hosts only (no infrastructure changes)    |
| **Routers**              | Unaware of S-IPv4, forward as normal IPv4     |
| **Kernel changes**       | Optional (user-space implementation possible) |
| **Incremental rollout**  | Clients and servers deploy independently      |
| **Legacy compatibility** | Non-S-IPv4 hosts continue working             |

---

# 14. Threat Model

## 14.1 Assumptions

S-IPv4 operates under the following threat assumptions:

1. **IPv4 Spoofing**: Attacker can forge source IPv4 addresses
2. **Packet Injection**: Attacker can craft and inject arbitrary packets into the network
3. **Packet Replay**: Attacker can capture and replay packets within the time window Δ
4. **Network Reordering**: Packets may arrive out of order naturally (by design)
5. **Packet Loss**: Link-layer packet loss occurs (by design)
6. **NAT Traversal**: Packets may traverse NAT devices that modify IP headers

## 14.2 Out of Scope

The following threats are **explicitly out of scope** for S-IPv4:

1. **Volumetric Attacks**: Bandwidth exhaustion / DDoS (mitigated by higher layers)
2. **Physical Link Attacks**: Electromagnetic eavesdropping, fiber tap
3. **Compromised Keys**: If epoch_key is stolen, security degrades (key management is separate concern)
4. **Application-Layer Exploits**: Vulnerabilities in application code
5. **Transport-Layer Attacks**: TCP/UDP sequence spoofing (QUIC handles this)
6. **BGP Hijacking**: Invalid route advertisement (Internet routing security)

## 14.3 Attacker Capabilities vs. S-IPv4 Defenses

| Attacker Action        | S-IPv4 Defense                                 |
| ---------------------- | ---------------------------------------------- |
| Spoof source IP        | Invalid HMAC token → packet dropped            |
| Inject random packet   | No valid token → packet dropped                |
| Replay old packet      | Timestamp check fails → packet dropped         |
| Modify QUIC ciphertext | HMAC verification fails → packet dropped       |
| Reorder packets        | Timestamp window allows reordering → tolerated |
| Traverse NAT           | Identity independent of IP → works             |

---

# 15. Packet Processing State Machine

## 15.1 Receiver-Side Decision Flow

```
                        START
                         ↓
                    RECEIVE_PACKET
                         ↓
                 [S-FLAG_PRESENT?]
                      /      \
                    YES       NO
                    /          \
                   ↓            ↓
            EXTRACT_HEADER    DROP_PACKET
                   ↓
            RESOLVE_EPOCH_KEY_
            FROM_NODEID
                   ↓
            RECOMPUTE_HMAC_TOKEN
                   ↓
                 [TOKEN_VALID?]
                      /      \
                    YES       NO
                    /          \
                   ↓            ↓
            CHECK_TIMESTAMP  DROP_PACKET
                   ↓
              [WITHIN_WINDOW Δ?]
                      /      \
                    YES       NO
                    /          \
                   ↓            ↓
         OPTIONAL_REPLAY_CHECK DROP_PACKET
         (BLOOM_FILTER)
                   ↓
              [NOT_REPLAY?]
                      /      \
                    YES       NO
                    /          \
                   ↓            ↓
            ACCEPT_PACKET    DROP_PACKET
                   ↓
            PASS_TO_QUIC_
            DECRYPTION
                   ↓
                  END
```

## 15.2 State Descriptions

| State                     | Action                                                            |
| ------------------------- | ----------------------------------------------------------------- |
| **EXTRACT_HEADER**        | Parse S-IPv4 mini-header from packet                              |
| **RESOLVE_EPOCH_KEY**     | Look up NodeID → retrieve current epoch_key from key store        |
| **RECOMPUTE_HMAC_TOKEN**  | Calculate HMAC(epoch_key, timestamp \| nonce \| payload_hash)     |
| **TOKEN_VALID**           | Compare computed HMAC with packet HMAC (constant-time comparison) |
| **CHECK_TIMESTAMP**       | Verify `\|current_time - packet_timestamp\| ≤ Δ`                  |
| **OPTIONAL_REPLAY_CHECK** | If Bloom filter enabled: check if nonce seen recently             |
| **ACCEPT_PACKET**         | Mark packet as legitimate, queue for decryption                   |
| **DROP_PACKET**           | Silently discard packet, update statistics                        |

---

# 16. Security Properties

S-IPv4 provides formally-defined security guarantees:

## 16.1 Packet Origin Authenticity (Cryptographic)

**Property**: A valid S-IPv4 token can only be generated by a node possessing the correct `epoch_key`.

**Proof**:

- HMAC is cryptographically secure under the assumption that SHA-256 is a secure pseudorandom function.
- Token = HMAC(epoch_key, timestamp | nonce | payload_hash)
- Without knowledge of epoch_key, computing a valid token requires 2^128 brute-force attempts (truncated HMAC).
- Probability of random token match: 2^(-128) per packet.

**Implication**: Spoofed IPv4 source addresses cannot produce valid tokens without the legitimate sender's key.

## 16.2 Payload Integrity

**Property**: Any modification to the QUIC ciphertext will invalidate the S-IPv4 HMAC token.

**Proof**:

- payload_hash = HASH(QUIC_ciphertext)
- Token depends on payload_hash
- If QUIC ciphertext is modified, payload_hash changes
- Token = HMAC(epoch_key, timestamp | nonce | changed_payload_hash) ≠ original token
- Receiver recomputes HMAC and detects mismatch.

**Implication**: In-path modification of packet payloads is cryptographically detectable.

## 16.3 Identity-Location Independence

**Property**: Node identity is decoupled from IP address.

**Proof**:

- S-IPv4 uses NodeID reference (4–8 bytes), not IP address, for key lookup.
- Token validity depends only on epoch_key and packet content, not source IPv4.
- NAT changes source IPv4 but does not affect S-IPv4 header (inside payload from routers' perspective).

**Implication**: Nodes can change IPv4 addresses (mobile, NAT, etc.) without token invalidation.

## 16.4 Bounded Replay Resistance

**Property**: Packets are rejected if timestamp falls outside the window: `|current_time - packet_timestamp| ≤ Δ`

**Proof**:

- Replay attacker must capture and retransmit packet within time window Δ.
- Minimum window Δ = max(clock skew, RTT variance, acceptable latency).
- Optional Bloom filter further reduces replay probability to 2^(-k) where k = Bloom filter size.

**Implication**: Replay attacks are bounded in time and can be virtually eliminated with recent nonce tracking.

## 16.5 No PKI Dependency

**Property**: S-IPv4 does not require a global public key infrastructure.

**Proof**:

- Keys are epoch-based and stored locally at each node.
- No certificate fetching, no OCSP, no revocation checking.
- Epoch rotation automatically "revokes" old keys.

**Implication**: S-IPv4 operates independently from PKI, reducing deployment friction.

---

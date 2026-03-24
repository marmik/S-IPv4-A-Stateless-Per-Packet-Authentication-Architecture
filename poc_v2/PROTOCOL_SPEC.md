# S-IPv4 V2 — Protocol Header Specifications

## 1. RFC-Style Header Bit-Field Diagrams

### 1.1 Full V2 Header (43 bytes, flag = 0x95)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   s_flag=0x95 |     key_ver (16-bit)          |    node_id    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       node_id (bytes 1–4)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  node_id (5-7)|                                               |
+-+-+-+-+-+-+-+-+           timestamp (64-bit)                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+            nonce (64-bit)                      +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+        hmac (128-bit, HMAC-SHA256              +
|                        truncated per NIST SP 800-107)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Offset | Bytes | Description |
|-------|--------|-------|-------------|
| s_flag | 0 | 1 | Magic byte 0x95 — identifies V2 full mode |
| key_ver | 1 | 2 | Epoch key version (network byte order) |
| node_id | 3 | 8 | Key-derived node identity (HMAC-SHA256 of epoch key, truncated to 64 bits) |
| timestamp | 11 | 8 | Unix time in seconds (big-endian) |
| nonce | 19 | 8 | 64-bit atomic counter nonce (big-endian) |
| hmac | 27 | 16 | HMAC-SHA256(epoch_key, SHA256(payload) || timestamp || nonce), truncated to 128 bits |
| **Total** | | **43** | **Per-packet overhead** |

### 1.2 Compact V2 Header (21 bytes, flag = 0x96)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   s_flag=0x96 |        node_id (32-bit, truncated)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   node_id(3)  |            nonce (32-bit, counter)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   nonce(3)    |                                               |
+-+-+-+-+-+-+-+-+            hmac (96-bit,                       +
|                   HMAC-SHA256 truncated per RFC 2404)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Offset | Bytes | Description |
|-------|--------|-------|-------------|
| s_flag | 0 | 1 | Magic byte 0x96 — identifies compact mode |
| node_id | 1 | 4 | Truncated node identity (first 4 bytes of full 8-byte ID) |
| nonce | 5 | 4 | 32-bit atomic counter nonce (network byte order) |
| hmac | 9 | 12 | HMAC-96: HMAC-SHA256(epoch_key, SHA256(payload) || nonce), truncated to 96 bits |
| **Total** | | **21** | **Per-packet overhead** |

### 1.3 Rejection Signal (10 bytes, msg_type = 0x02)

| Field | Offset | Bytes | Description |
|-------|--------|-------|-------------|
| s_flag | 0 | 1 | 0x95 or 0x96 |
| msg_type | 1 | 1 | 0x02 = REJECT |
| node_id | 2 | 8 | Target node being rejected |

---

## 2. HMAC Truncation Security Justification

### 2.1 Full Mode (128-bit truncation)

Per **NIST SP 800-107 Rev. 1, §5.3.4** (Recommendation for Applications Using Approved Hash Algorithms):

> "HMAC-SHA-256 truncated to t bits provides at minimum t/2 bits of security against forgery attacks."

For S-IPv4 V2 full mode:
- **Untruncated HMAC-SHA-256** produces a 256-bit tag
- **Truncated to 128 bits** (16 bytes)
- **Security level**: 64-bit security against forgery under the PRF assumption for HMAC-SHA-256
- **Forgery probability**: An attacker must perform ≈ 2^64 HMAC computations to find a valid tag collision
- **At 10 billion attempts/second**: ~58 years to find a collision
- **Comparison**: IPsec AH recommends 96-bit truncation (HMAC-96, RFC 2404), providing only 48-bit security. S-IPv4 V2 full mode exceeds this with 64-bit security.

### 2.2 Compact Mode (96-bit truncation)

For S-IPv4 V2 compact mode:
- **Truncated to 96 bits** (12 bytes) per **RFC 2404** (The Use of HMAC-SHA-96 within ESP and AH)
- **Security level**: 48-bit security against forgery
- **Trade-off**: The compact mode intentionally accepts lower security for constrained/IoT environments where bandwidth savings (21 bytes vs 43 bytes = 51% reduction) are critical
- **Mitigation**: Compact mode omits the timestamp field, relying solely on nonce uniqueness for replay protection. This is acceptable for short-lived sessions where the 32-bit nonce space (4.3 billion packets) is sufficient.

### 2.3 Citation Chain
- NIST SP 800-107 Rev. 1 (August 2012) — HMAC truncation security bounds
- RFC 2104 (February 1997) — HMAC specification
- RFC 2404 (November 1998) — HMAC-SHA-96 for IPsec
- FIPS 198-1 (July 2008) — The Keyed-Hash Message Authentication Code

---

## 3. DTLS-PSK Differentiation

### 3.1 Why Not DTLS-PSK?

**DTLS (RFC 6347)** with Pre-Shared Key mode **(RFC 4279)** is the most obvious alternative to S-IPv4's approach. Both provide:
- Per-datagram authentication over UDP
- No PKI dependency (pre-shared keys)
- NAT transparency

However, critical architectural differences make S-IPv4 preferable for its target use case:

| Property | DTLS-PSK | S-IPv4 V2 |
|----------|----------|-----------|
| **Handshake** | Required (2 RTT minimum) | None — stateless |
| **Per-connection state** | Yes (session context, sequence numbers) | None — stateless |
| **Replay protection** | Implicit sliding window per session | Probabilistic Bloom filter (bounded memory) |
| **Server memory at 100k peers** | ~100k × session context ≈ 50+ MiB | Single tiered Bloom filter ≈ 14.7 MiB (fixed) |
| **First-packet latency** | Handshake RTT + crypto | Zero — immediate send |
| **Connection migration** | New handshake on IP change | Transparent — no session state |
| **Header overhead** | 13+ bytes (content type, epoch, sequence, length) | 43 bytes (full) / 21 bytes (compact) |
| **Cryptographic agility** | Full cipher suite negotiation | Fixed HMAC-SHA-256 |

### 3.2 Key Distinction

S-IPv4 is **not a transport security protocol** — it is a **per-packet origin authentication shim**. Its design goal is to authenticate the source of *every individual packet* without establishing any session state. DTLS-PSK, while avoiding PKI, still requires session establishment and per-connection state maintenance, making it unsuitable for scenarios where millions of unconnected peers send sporadic datagrams to a single receiver.

### 3.3 When to Use DTLS-PSK Instead
- When bidirectional encrypted communication is needed
- When cipher suite negotiation is required
- When connection-oriented semantics are available
- When the number of concurrent peers is manageable (hundreds, not millions)

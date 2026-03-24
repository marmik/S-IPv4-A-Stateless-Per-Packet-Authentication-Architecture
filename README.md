# S-IPv4
## A Stateless Per-Packet Authentication Architecture

### Status Console

- Protocol class: Stateless packet-authentication overlay for IPv4
- Codebase: C proof-of-concept (V1 legacy + V2 upgrade) + benchmark harness
- Focus: Replay resistance, dynamic key derivation, tiered adaptive filtering, low-latency verification path

---

## Why S-IPv4

S-IPv4 explores a security model where every packet carries enough verifiable context to be authenticated without maintaining heavy per-flow state. The PoC is designed to evaluate feasibility, behavior under attack-like traffic patterns, and measurable overhead.

### V2 Upgrade Features (IEEE Expert Review Aligned)

The `poc_v2` directory contains the updated architectural design strictly aligning with production requirements:
- **Header Protocol Versioning:** Explicit 1-byte magic flag (`0x95`) mapping to S-IPv4 Version 2.0.
- **Stateless Fragmentation Protection:** Strict `IP_DONTFRAG` socket enforcement and 1431-byte MTU guard.
- **Epoch Key Strategy:** Secure hierarchical key derivation (HKDF) mapping master secrets to node-specific tokens, explicitly tracking key generation lifecycles (`key_ver`).
- **Resilient Replay Protection:** A three-tier Adaptive Bloom filter triggering `DEGRADED_MODE` automatically using monotonic clock anchors to eliminate reliance on spoofable system NTP clocks.
- **Cryptography Migration:** Total deprecation of old OpenSSL hooks, re-implemented natively over OpenSSL 3.0 `EVP_MAC` primitives.

---

## Repository Atlas

```text
S-IPv4/
|- poc/                    # V1 Legacy PoC implementation
|  |- bench/               # Benchmark suite and artifacts
|- poc_v2/                 # V2 Upgraded PoC implementation (compliant)
|  |- bench/               # Dedicated V2 benchmark suite
|  |- test_run.sh          # Automated V1/V2 hybrid validation sequence
|  |- Makefile             # Build entrypoint (OpenSSL 3.0 EVP_MAC clean)

|- s_ipv4_paper.tex        # Primary LaTeX manuscript
|- S-IPv4-Architecture.md  # Architecture and design notes
|- full_paper_draft.md     # Draft narrative
|- working.md              # Working notes
```

---

## Local Environment

Target environment:

- macOS or Linux
- Xcode command line tools (`cc`, `make`)
- OpenSSL from Homebrew / System (auto-detected by the Makefile)

Install dependency:

```bash
brew install openssl
```

---

## Quick Start

### 1. Build PoC binaries

To build the standard V2 compliance testbed:

```bash
cd poc_v2
make clean
make all
```

Expected outputs:

- `poc_v2/client`
- `poc_v2/server`

*(Note: V1 legacy binaries can be identically built from the `poc/` directory.)*

### 2. Run the verification suite

The comprehensive verification suite encompasses 15 security phases tracking backwards compatibility and V2 protocol enhancements.

```bash
cd poc_v2
./test_run.sh
```

Test suite coverage includes:

- Valid packet acceptance
- Replay detection (Strict tier simulation via `--force-fill`)
- Expired timestamp rejection
- Forged HMAC rejection
- NodeID spoof rejection
- Truncated packet handling
- AUDIT mode logging with payload forwarding behavior
- V2 exclusive: Version flag corruption testing
- V2 exclusive: Deterministic NodeID distribution tracking
- V2 exclusive: Deterministic `key_ver` persistence guarantees
- V2 exclusive: Absolute Maximum Transmission Unit (MTU) testing

### 3. Run the full benchmark pipeline

```bash
cd poc_v2/bench
./run_all_benchmarks.sh
```

Primary generated artifacts:

- `poc_v2/bench/results.txt`
- Benchmark PDF figures in `poc_v2/bench/`

---

## Data + Figure Pipeline

The benchmark orchestrator compiles and runs four benchmark lanes:

1. Token generation latency
2. Full verification latency
3. Throughput and overhead
4. Bloom filter memory and false-positive behavior

It then emits summary metrics and publication-ready figures.

---

## Operating Modes

- `ENFORCE`: invalid packets are rejected
- `AUDIT`: invalid packets are logged while payload delivery behavior can be observed

This split allows security validation and compatibility experimentation without changing core binaries.

---

## Research Note

This repository is a research-grade proof-of-concept evaluated under strict IEEE architectural scrutiny. It is intended for experimentation, evaluation, and paper reproducibility work rather than direct production deployment without extensive multi-node validation setups.
# S-IPv4
## A Stateless Per-Packet Authentication Architecture

### Status Console

- Protocol class: Stateless packet-authentication overlay for IPv4
- Codebase: C proof-of-concept + benchmark harness + paper artifacts
- Focus: Replay resistance, token validation, low-latency verification path

---

## Why S-IPv4

S-IPv4 explores a security model where every packet carries enough verifiable context to be authenticated without maintaining heavy per-flow state. The PoC is designed to evaluate feasibility, behavior under attack-like traffic patterns, and measurable overhead.

---

## Repository Atlas

```text
S-IPv4/
|- poc/                    # Core PoC implementation (client/server + shared modules)
|  |- bench/               # Benchmark suite, scripts, generated figures, raw outputs
|  |- test_run.sh          # Automated ENFORCE/AUDIT verification sequence
|  |- Makefile             # Build entrypoint for PoC binaries
|- s_ipv4_paper.tex        # Primary LaTeX manuscript
|- S-IPv4-Architecture.md  # Architecture and design notes
|- full_paper_draft.md     # Draft narrative
|- working.md              # Working notes
|- s-ipv4.txt              # Additional draft material
```

---

## Local Environment

Target environment:

- macOS
- Xcode command line tools (`cc`, `make`)
- OpenSSL from Homebrew (auto-detected by the Makefile)

Install dependency:

```bash
brew install openssl
```

---

## Quick Start

### 1. Build PoC binaries

```bash
cd poc
make clean
make all
```

Expected outputs:

- `poc/client`
- `poc/server`

### 2. Run the verification suite

```bash
cd poc
./test_run.sh
```

Test suite coverage includes:

- Valid packet acceptance
- Replay detection
- Expired timestamp rejection
- Forged HMAC rejection
- NodeID spoof rejection
- Truncated packet handling
- AUDIT mode logging with payload forwarding behavior

### 3. Run the full benchmark pipeline

```bash
cd poc/bench
./run_all_benchmarks.sh
```

Primary generated artifacts:

- `poc/bench/results.txt`
- Benchmark PDF figures in `poc/bench/`

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

This repository is a research-grade proof-of-concept. It is intended for experimentation, evaluation, and paper reproducibility work rather than direct production deployment.
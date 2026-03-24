# S-IPv4

Stateless Per-Packet Authentication for IPv4.

S-IPv4 is a research architecture that adds cryptographic packet legitimacy checks without modifying the IPv4 header and without requiring per-flow server state. The current implementation includes a legacy V1 PoC and a V2 upgrade with protocol versioning, epoch-aware keying, adaptive replay defense, and reproducible benchmarks.

## Why This Matters

S-IPv4 targets a specific systems problem: authenticate packet origin and integrity at line-rate style paths where connection setup and large session state are undesirable.

Core design intent:
- Keep IPv4 unchanged and incrementally deployable.
- Authenticate each packet independently.
- Preserve NAT compatibility.
- Bound replay risk with timestamp windows plus probabilistic nonce tracking.
- Keep verification latency low and measurable.

## What Is New In V2

The active implementation in `poc_v2/` introduces the following major upgrades:

- Protocol version signaling via explicit magic flags (`0x95` full mode, `0x96` compact mode in spec).
- `key_ver` in header for key-rotation-safe verification.
- Epoch-key lifecycle and deterministic `node_id` derivation.
- Monotonic-clock anchored replay windowing.
- Three-tier adaptive Bloom strategy with automatic degraded-mode activation under saturation.
- OpenSSL 3 `EVP_MAC` migration for core protocol binaries.
- Extended verification harness with V2-specific checks.

Design rationale and architecture details are documented in:
- `S-IPv4-Architecture.md`
- `poc_v2/PROTOCOL_SPEC.md`
- `CHANGELOG.md`

## Repository Layout

```text
S-IPv4/
	poc/                         # V1 legacy PoC
		bench/                     # V1 benchmarks

	poc_v2/                      # Active V2 PoC
		Makefile                   # Build client/server
		test_run.sh                # Automated V1+V2 validation
		PROTOCOL_SPEC.md           # Header formats + security notes
		bench/                     # V2 benchmark suite
			run_all_benchmarks.sh
			results.txt
			plot_latency.py

	s_ipv4_paper.tex             # Main manuscript source
	full_paper_draft.md          # Paper draft notes
	S-IPv4-Architecture.md       # Architecture reference
	CHANGELOG.md                 # Versioned protocol evolution
```

## Quickstart

### 1) Prerequisites

- macOS or Linux
- C toolchain (`cc`, `make`)
- OpenSSL (Homebrew path is auto-detected by the Makefile)

Install on macOS:

```bash
brew install openssl
```

### 2) Build V2 Client/Server

```bash
cd poc_v2
make clean
make all
```

Build outputs:
- `poc_v2/client`
- `poc_v2/server`

### 3) Run Security Verification Suite

```bash
cd poc_v2
./test_run.sh
```

The suite covers ENFORCE and AUDIT behavior plus V2-specific protocol assertions, including:
- valid packet acceptance
- replay detection
- expired timestamp rejection
- forged token rejection
- spoofed identity rejection
- truncated packet handling
- bad version-flag rejection
- deterministic node identity behavior
- key-version visibility
- adaptive filter stress path activation

### 4) Run Full Benchmark Pipeline

```bash
cd poc_v2/bench
./run_all_benchmarks.sh
```

Generated artifacts:
- `poc_v2/bench/results.txt`
- figure PDFs (if `python3` + plotting deps are available)

## Protocol Snapshot

S-IPv4 adds a shim header between transport payload and IPv4 forwarding path. IPv4 itself is not modified.

V2 full header (`s_flag = 0x95`) includes:
- `key_ver` (16-bit)
- `node_id` (64-bit)
- `timestamp` (64-bit)
- `nonce` (64-bit)
- truncated HMAC-SHA256 (128-bit)

V2 compact mode (`s_flag = 0x96`) is specified for reduced overhead deployments with different security/overhead trade-offs.

See `poc_v2/PROTOCOL_SPEC.md` for exact bit-level definitions and cryptographic truncation rationale.

## Benchmark Coverage

The V2 benchmark harness executes four lanes:
1. token generation latency
2. end-to-end verification latency
3. throughput and overhead
4. replay-filter memory and false-positive behavior

`run_all_benchmarks.sh` emits machine info, structured metrics, and paper-ready summary lines in `results.txt`.

## Operating Modes

- `ENFORCE`: invalid packets are rejected.
- `AUDIT`: invalid packets are logged while payload path behavior remains observable.

This supports both strict security validation and compatibility experiments without rebuilding binaries.

## Security Model (Scope)

S-IPv4 is designed to provide:
- per-packet authenticity checks
- packet integrity validation
- bounded replay mitigation
- spoofing resistance at the authentication layer

S-IPv4 does not aim to replace:
- transport confidentiality (handled by protocols such as QUIC/TLS)
- reliability/ordering semantics
- full anti-replay guarantees under all adversarial network conditions

## Reproducibility Notes

For publication-style reproducibility:
- run tests via `poc_v2/test_run.sh`
- run benchmarks via `poc_v2/bench/run_all_benchmarks.sh`
- capture generated `results.txt` and figure PDFs
- record compiler, OpenSSL version, CPU model, and OS build in experiment notes

## Development Status

- V1 (`poc/`) is retained as legacy baseline.
- V2 (`poc_v2/`) is the active implementation track.
- The project is research-grade and not production-hardened for unbounded internet deployment.

## Citation

If you use this code or architecture in academic work, cite the repository and accompanying manuscript source (`s_ipv4_paper.tex`).
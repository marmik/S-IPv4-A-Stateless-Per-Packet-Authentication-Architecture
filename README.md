# S-IPv4: A Stateless Per-Packet Authentication Architecture

This repository contains the S-IPv4 paper artifacts and a C proof-of-concept (PoC) implementation for stateless per-packet authentication.

## Repository layout

- `poc/`: C implementation of the PoC, test harness, and benchmark suite.
- `poc/bench/`: Benchmark binaries, scripts, sample data, and generated figures.
- `s_ipv4_paper.tex`: Main LaTeX paper source.
- `full_paper_draft.md`, `working.md`, `S-IPv4-Architecture.md`, `s-ipv4.txt`: Draft and architecture notes.

## Prerequisites

- macOS with Xcode command line tools (`cc`, `make`)
- OpenSSL (Homebrew expected by the PoC Makefile)

Install OpenSSL if needed:

```bash
brew install openssl
```

## Build the PoC

From repository root:

```bash
cd poc
make clean
make all
```

This produces:

- `poc/client`
- `poc/server`

## Run automated verification

```bash
cd poc
./test_run.sh
```

The script runs ENFORCE and AUDIT mode tests, including replay, expired timestamp, forged HMAC, spoofing, and truncated-packet scenarios.

## Run benchmarks

```bash
cd poc/bench
./run_all_benchmarks.sh
```

Outputs include:

- `poc/bench/results.txt`
- PDF figures under `poc/bench/` (for example latency CDF and overhead comparison plots)

## Notes

- The PoC is intended for research and evaluation purposes.
- Existing binaries and figure artifacts are currently tracked in the repository as produced artifacts.
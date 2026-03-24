#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# run_all_benchmarks.sh — Orchestrate full S-IPv4 benchmark suite
#
# Runs all four benchmarks, collects structured output into
# bench/results.txt, then optionally invokes plot_latency.py.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RESULTS="results.txt"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     S-IPv4 Benchmark Suite — Full Evaluation Run         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ── Build ──────────────────────────────────────────────────────────
echo "▶ Building benchmark binaries..."
make -s clean
make -s all
echo ""

# ── Clear previous results ─────────────────────────────────────────
> "$RESULTS"
echo "# S-IPv4 Benchmark Results" >> "$RESULTS"
echo "# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$RESULTS"
echo "# Host: $(uname -mnrs)" >> "$RESULTS"
echo "# CPU: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)" >> "$RESULTS"
echo "" >> "$RESULTS"

# ═══════════════════════════════════════════════════════════════════
#  1. HMAC Token Generation Latency
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [1/4] HMAC Token Generation Latency"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "# 1. HMAC Token Generation Latency (µs)" >> "$RESULTS"
echo "# CRYPTO_BENCH mean std min max p50 p95 p99" >> "$RESULTS"
./bench_crypto >> "$RESULTS"
echo "" >> "$RESULTS"
echo ""

# ═══════════════════════════════════════════════════════════════════
#  2. Full Verification Latency
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [2/4] Full Verification Path Latency"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "# 2. Full Verification Latency (µs)" >> "$RESULTS"
echo "# VERIFY_BENCH mean std min max p50 p95 p99" >> "$RESULTS"
./bench_verify >> "$RESULTS"
echo "" >> "$RESULTS"
echo ""

# ═══════════════════════════════════════════════════════════════════
#  3. Throughput Benchmark
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [3/4] Throughput Benchmark"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "# 3. Throughput Benchmark" >> "$RESULTS"
echo "# THROUGHPUT_BENCH N mode pps mbps total_sec" >> "$RESULTS"
echo "# THROUGHPUT_OVERHEAD N time_overhead_pct bw_overhead_pct" >> "$RESULTS"
./bench_throughput >> "$RESULTS"
echo "" >> "$RESULTS"
echo ""

# ═══════════════════════════════════════════════════════════════════
#  4. Bloom Filter Memory
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [4/4] Bloom Filter Memory Footprint"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "# 4. Bloom Filter Memory" >> "$RESULTS"
echo "# MEMORY_BENCH nonces filter_kb total_kb fp_rate_pct fill_pct" >> "$RESULTS"
./bench_memory >> "$RESULTS"
echo "" >> "$RESULTS"
echo ""

# ═══════════════════════════════════════════════════════════════════
#  Generate LaTeX-ready summary table
# ═══════════════════════════════════════════════════════════════════
echo "# ────────────────────────────────────────────────────────" >> "$RESULTS"
echo "# LaTeX Table Data (copy into tabular environment)" >> "$RESULTS"
echo "# ────────────────────────────────────────────────────────" >> "$RESULTS"

# Extract key numbers
CRYPTO_LINE=$(grep "^CRYPTO_BENCH" "$RESULTS")
VERIFY_LINE=$(grep "^VERIFY_BENCH" "$RESULTS")

C_MEAN=$(echo "$CRYPTO_LINE" | awk -F'\t' '{print $2}')
C_P95=$(echo "$CRYPTO_LINE"  | awk -F'\t' '{print $7}')
C_P99=$(echo "$CRYPTO_LINE"  | awk -F'\t' '{print $8}')

V_MEAN=$(echo "$VERIFY_LINE" | awk -F'\t' '{print $2}')
V_P95=$(echo "$VERIFY_LINE"  | awk -F'\t' '{print $7}')
V_P99=$(echo "$VERIFY_LINE"  | awk -F'\t' '{print $8}')

# Memory at 1M
MEM_1M=$(grep "^MEMORY_BENCH" "$RESULTS" | grep "1000000" | awk -F'\t' '{print $4}')
FP_1M=$(grep "^MEMORY_BENCH" "$RESULTS" | grep "1000000" | awk -F'\t' '{print $5}')

# Throughput overhead at 1M
OVHD_1M=$(grep "^THROUGHPUT_OVERHEAD" "$RESULTS" | grep "1000000" | awk -F'\t' '{print $3}')

cat >> "$RESULTS" <<EOF
#
# Key Numbers for Paper:
#   Token Gen Mean:    ${C_MEAN} µs
#   Token Gen P99:     ${C_P99} µs
#   Verification Mean: ${V_MEAN} µs
#   Verification P99:  ${V_P99} µs
#   Bloom Memory (1M): ${MEM_1M} KiB (dual-window)
#   BF FP Rate (1M):   ${FP_1M}%
#   Throughput Overhead (1M pkts): ${OVHD_1M}%
EOF

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results written to: bench/results.txt"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Optional: generate plots ───────────────────────────────────────
if command -v python3 &>/dev/null; then
    echo "▶ Generating publication figures..."
    python3 plot_latency.py
    echo ""
    echo "  Figures saved:"
    echo "    bench/fig_latency_cdf.pdf"
    echo "    bench/fig_overhead_comparison.pdf"
else
    echo "⚠  python3 not found — skipping figure generation."
    echo "   Install matplotlib and run: python3 plot_latency.py"
fi

echo ""
echo "🟢  Benchmark suite complete."

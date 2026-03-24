#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# test_run.sh — Automated S-IPv4 PoC verification script
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT_ENFORCE=9990
PORT_AUDIT=9991
PORT_V2=9992
PASS=0; FAIL=0
V1_PASS=0; V1_FAIL=0
V2_PASS=0; V2_FAIL=0

# ── Cleanup on exit ────────────────────────────────────────────────
PIDS_TO_KILL=()
cleanup() {
    for pid in "${PIDS_TO_KILL[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# ── Helpers ────────────────────────────────────────────────────────
pass_v1() { PASS=$((PASS+1)); V1_PASS=$((V1_PASS+1)); printf "  ✅  PASS: %s
" "$1"; }
fail_v1() { FAIL=$((FAIL+1)); V1_FAIL=$((V1_FAIL+1)); printf "  ❌  FAIL: %s
" "$1"; }
pass_v2() { PASS=$((PASS+1)); V2_PASS=$((V2_PASS+1)); printf "  ✅  PASS: %s
" "$1"; }
fail_v2() { FAIL=$((FAIL+1)); V2_FAIL=$((V2_FAIL+1)); printf "  ❌  FAIL: %s
" "$1"; }

expect_server_v1() {
    # $1 = description, $2 = pattern to grep, $3 = log file
    if grep -q "$2" "$3"; then
        pass_v1 "$1"
    else
        fail_v1 "$1 (expected '$2' in server output)"
    fi
}

expect_server_v2() {
    # $1 = description, $2 = pattern to grep, $3 = log file
    if grep -q "$2" "$3"; then
        pass_v2 "$1"
    else
        fail_v2 "$1 (expected '$2' in server output)"
    fi
}

# ═══════════════════════════════════════════════════════════════════
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║        S-IPv4 Proof of Concept — Test Suite              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ── Build ──────────────────────────────────────────────────────────
echo "▶ Building..."
make -s clean
make -s all
echo ""

# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: ENFORCE MODE
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PHASE 1: ENFORCE MODE (port $PORT_ENFORCE)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ENFORCE_LOG=$(mktemp)
./server $PORT_ENFORCE ENFORCE > "$ENFORCE_LOG" 2>&1 &
SERVER_PID=$!
PIDS_TO_KILL+=("$SERVER_PID")
sleep 1

# ── Test 1: Valid fresh packet ─────────────────────────────────
echo ""
echo "  [Test 1] Valid fresh packet"
CLIENT_OUT=$(./client 127.0.0.1 $PORT_ENFORCE "Hello S-IPv4!")
echo "    Client: $CLIENT_OUT"
sleep 0.3
expect_server_v1 "Valid packet accepted" "ACCEPT_OK" "$ENFORCE_LOG"

# Capture nonce and timestamp for replay test
NONCE=$(echo "$CLIENT_OUT" | head -1 | sed -n 's/.*Nonce: \(0x[0-9A-Fa-f]*\).*/\1/p')
TIMESTAMP=$(echo "$CLIENT_OUT" | head -1 | sed -n 's/.*Timestamp: \([0-9]*\).*/\1/p')

# ── Test 2: Exact replay (same nonce + timestamp → Bloom filter) ─
echo ""
echo "  [Test 2] Exact replay (nonce=$NONCE ts=$TIMESTAMP)"
./client 127.0.0.1 $PORT_ENFORCE "Hello S-IPv4!" --replay "$NONCE" "$TIMESTAMP" > /dev/null 2>&1
sleep 0.3
expect_server_v1 "Replay detected" "REPLAY_DETECTED" "$ENFORCE_LOG"

# ── Test 3: Fresh nonce + expired timestamp (isolates timestamp) ─
echo ""
EXPIRED_TS=$((TIMESTAMP - 600))
echo "  [Test 3] Fresh nonce + expired timestamp ($EXPIRED_TS)"
./client 127.0.0.1 $PORT_ENFORCE "Hello S-IPv4!" --replay "0xDEADBEEFCAFE0001" "$EXPIRED_TS" > /dev/null 2>&1
sleep 0.3
expect_server_v1 "Expired timestamp rejected" "EXPIRED_TIMESTAMP" "$ENFORCE_LOG"

# ── Test 4: Forged HMAC ───────────────────────────────────────────
echo ""
echo "  [Test 4] Forged HMAC token"
./client 127.0.0.1 $PORT_ENFORCE "Hello S-IPv4!" --bad-hmac > /dev/null 2>&1
sleep 0.3
expect_server_v1 "Bad HMAC rejected" "INVALID_TOKEN" "$ENFORCE_LOG"

# ── Test 5: NodeID spoofing (correct NodeID, wrong key) ──────────
echo ""
echo "  [Test 5] NodeID spoofing"
./client 127.0.0.1 $PORT_ENFORCE "Hello S-IPv4!" --spoof-node > /dev/null 2>&1
sleep 0.3
expect_server_v1 "Spoofed NodeID rejected" "INVALID_TOKEN" "$ENFORCE_LOG"

# ── Test 6: Truncated packet ─────────────────────────────────────
echo ""
echo "  [Test 6] Truncated packet (3 bytes)"
./client 127.0.0.1 $PORT_ENFORCE --truncated > /dev/null 2>&1
sleep 0.3
expect_server_v1 "Truncated packet rejected" "TRUNCATED" "$ENFORCE_LOG"

# ── Kill ENFORCE server ───────────────────────────────────────────
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════════════════════
#  PHASE 2: AUDIT MODE
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PHASE 2: AUDIT MODE (port $PORT_AUDIT)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

AUDIT_LOG=$(mktemp)
./server $PORT_AUDIT AUDIT > "$AUDIT_LOG" 2>&1 &
SERVER_PID=$!
PIDS_TO_KILL+=("$SERVER_PID")
sleep 1

# ── Test 7: AUDIT — NodeID spoofing (should log + deliver) ───────
echo ""
echo "  [Test 7] AUDIT: NodeID spoofing — payload should be delivered"
./client 127.0.0.1 $PORT_AUDIT "AuditPayload1" --spoof-node > /dev/null 2>&1
sleep 0.3
expect_server_v1 "AUDIT_FAIL logged for spoofed NodeID" "AUDIT_FAIL.*INVALID_TOKEN" "$AUDIT_LOG"
expect_server_v1 "Payload still delivered in AUDIT" "AuditPayload1" "$AUDIT_LOG"

# ── Test 8: AUDIT — Forged HMAC (different code path) ────────────
echo ""
echo "  [Test 8] AUDIT: Forged HMAC — payload should be delivered"
./client 127.0.0.1 $PORT_AUDIT "AuditPayload2" --bad-hmac > /dev/null 2>&1
sleep 0.3
expect_server_v1 "AUDIT_FAIL logged for bad HMAC" "AUDIT_FAIL.*INVALID_TOKEN" "$AUDIT_LOG"
expect_server_v1 "Payload still delivered in AUDIT" "AuditPayload2" "$AUDIT_LOG"

# ── Kill AUDIT server ─────────────────────────────────────────────
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════
#  PHASE 3: V2-SPECIFIC TESTS
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PHASE 3: V2 PROTOCOL TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

V2_LOG=$(mktemp)
./server $PORT_V2 ENFORCE > "$V2_LOG" 2>&1 &
SERVER_PID=$!
PIDS_TO_KILL+=("$SERVER_PID")
sleep 1

# V2 Test 1 — Bad version flag 
echo ""
echo "  [V2 Test 1] Bad version flag"
./client 127.0.0.1 $PORT_V2 "Hello S-IPv4!" --v1-flag > /dev/null 2>&1
sleep 0.3
expect_server_v2 "Bad version flag rejected" "BAD_VERSION" "$V2_LOG"

# V2 Test 2 — NodeID derivation consistency
echo ""
echo "  [V2 Test 2] NodeID derivation consistency"
NODEID1=$(cat "$V2_LOG" | grep -m 1 "NodeID:" | sed -n 's/.*NodeID: \([0-9A-F]*\).*/\1/p')

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# Restart server
V2_LOG2=$(mktemp)
./server $PORT_V2 ENFORCE > "$V2_LOG2" 2>&1 &
SERVER_PID=$!
PIDS_TO_KILL+=("$SERVER_PID")
sleep 1

NODEID2=$(cat "$V2_LOG2" | grep -m 1 "NodeID:" | sed -n 's/.*NodeID: \([0-9A-F]*\).*/\1/p')
if [ -n "$NODEID1" ] && [ "$NODEID1" == "$NODEID2" ]; then
    pass_v2 "NodeID derivation consistency (${NODEID1})"
else
    fail_v2 "NodeID derivation consistency (${NODEID1} != ${NODEID2})"
fi

# V2 Test 3 — Payload size enforcement (client fails)
echo ""
echo "  [V2 Test 3] Payload size enforcement"
set +e
CLIENT_RES=$(./client 127.0.0.1 $PORT_V2 "Big Payload" --oversize 2>&1)
set -e
if [[ "$CLIENT_RES" == *"Payload exceeds S_IPV4_MAX_PAYLOAD"* ]]; then
    pass_v2 "Payload size enforcement (Client rejected oversize)"
else
    fail_v2 "Payload size enforcement ($CLIENT_RES)"
fi

# V2 Test 4 — Adaptive Bloom activation
echo ""
echo "  [V2 Test 4] Adaptive Bloom activation"
./client 127.0.0.1 $PORT_V2 "Flood" --force-fill=1700000 > /dev/null 2>&1
sleep 0.5
if grep -q "DEGRADED_MODE activated" "$V2_LOG2"; then
    pass_v2 "Adaptive Bloom activated (fill > 80%)"
else
    fail_v2 "Adaptive Bloom not activated under flood"
fi

# V2 Test 5 — key_ver field present
echo ""
echo "  [V2 Test 5] key_ver field present"
./client 127.0.0.1 $PORT_V2 "Hello S-IPv4!" > /dev/null 2>&1
sleep 0.3
expect_server_v2 "key_ver field present" "key_ver:1" "$V2_LOG2"

# ── Kill V2 server ─────────────────────────────────────────────
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "  V1 Tests:  %d passed, %d failed\n" "$V1_PASS" "$V1_FAIL"
printf "  V2 Tests:  %d passed, %d failed\n" "$V2_PASS" "$V2_FAIL"
printf "  ─────────────────────────────────────────────────────\n"
printf "  Total:     %d passed, %d failed\n" "$PASS" "$FAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" 
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "🔴  SOME TESTS FAILED"
    exit 1
else
    echo "🟢  ALL TESTS PASSED"
    exit 0
fi

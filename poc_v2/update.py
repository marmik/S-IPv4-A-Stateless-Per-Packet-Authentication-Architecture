import re

with open("poc_v2/test_run.sh", "r") as f:
    text = f.read()

# Change 1: PASS/FAIL variables
text = text.replace("PASS=0\nFAIL=0", "PASS=0; FAIL=0\nV1_PASS=0; V1_FAIL=0\nV2_PASS=0; V2_FAIL=0")

# Change 2 & 3: Helpers
new_helpers = """pass_v1() { PASS=$((PASS+1)); V1_PASS=$((V1_PASS+1)); printf "  ✅  PASS: %s\\n" "$1"; }
fail_v1() { FAIL=$((FAIL+1)); V1_FAIL=$((V1_FAIL+1)); printf "  ❌  FAIL: %s\\n" "$1"; }
pass_v2() { PASS=$((PASS+1)); V2_PASS=$((V2_PASS+1)); printf "  ✅  PASS: %s\\n" "$1"; }
fail_v2() { FAIL=$((FAIL+1)); V2_FAIL=$((V2_FAIL+1)); printf "  ❌  FAIL: %s\\n" "$1"; }

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
"""

text = re.sub(r"pass\(\) \{ [^\}]+\}\nfail\(\) \{ [^\}]+\}\n\nexpect_server\(\) \{\n(?:.*\n)*?\}", new_helpers.strip(), text, flags=re.MULTILINE)

# Split into phases
parts = text.split("  PHASE 3: V2 PROTOCOL TESTS")
phase_1_2 = parts[0]
phase_3 = parts[1]

# Phase 1 and 2 updates
phase_1_2 = phase_1_2.replace("expect_server ", "expect_server_v1 ")
phase_1_2 = phase_1_2.replace("pass ", "pass_v1 ")
phase_1_2 = phase_1_2.replace("fail ", "fail_v1 ")

# Phase 3 updates
phase_3 = phase_3.replace("expect_server ", "expect_server_v2 ")
phase_3 = phase_3.replace("pass ", "pass_v2 ")
phase_3 = phase_3.replace("fail ", "fail_v2 ")

text = phase_1_2 + "  PHASE 3: V2 PROTOCOL TESTS" + phase_3

# Summary replace
summary = """echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "  V1 Tests:  %d passed, %d failed\\n" "$V1_PASS" "$V1_FAIL"
printf "  V2 Tests:  %d passed, %d failed\\n" "$V2_PASS" "$V2_FAIL"
printf "  ─────────────────────────────────────────────────────\\n"
printf "  Total:     %d passed, %d failed\\n" "$PASS" "$FAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" """
# Just replace the summary portion exactly:
text = text.replace('echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"\nprintf "  Results: %d passed, %d failed | Total: 15\\n" "$PASS" "$FAIL"\necho "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"', summary)

with open("poc_v2/test_run.sh", "w") as f:
    f.write(text)

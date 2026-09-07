#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HvccAtom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_001.mp4"
RESULT="$POC_DIR/vuln_001_result.txt"

echo "=== Step 1: Generate PoC MP4 ===" | tee "$RESULT"
python3 "$POC_DIR/vuln_001_gen.py" | tee -a "$RESULT"

echo "" | tee -a "$RESULT"
echo "=== Step 2: Run mp42aac with ASAN ===" | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
    "$BINARY" \
    "$INPUT" \
    /dev/null \
    >> "$RESULT" 2>&1 || true

echo "" | tee -a "$RESULT"
echo "=== Step 3: ASAN/UBSAN errors ===" | tee -a "$RESULT"
grep -h "ERROR\|SUMMARY\|heap-buffer-overflow\|READ\|WRITE\|oob\|out-of-bounds\|runtime error" \
    "$POC_DIR"/asan.log.* 2>/dev/null \
    >> "$RESULT" || true

echo "" | tee -a "$RESULT"
echo "=== Done ===" | tee -a "$RESULT"

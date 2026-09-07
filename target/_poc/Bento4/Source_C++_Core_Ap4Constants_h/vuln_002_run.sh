#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Constants_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_002.mp4"
RESULT="$POC_DIR/vuln_002_result.txt"
ASAN_LOG_PREFIX="$POC_DIR/asan_002.log"

# Step 1: Generate the malicious MP4
echo "[*] Generating PoC input..."
python3 "$POC_DIR/vuln_002_gen.py"

# Step 2: Run mp42aac under ASAN
echo "[*] Running mp42aac..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "$BINARY" \
  "$INPUT" \
  /dev/null \
  > "$RESULT" 2>&1 || true

echo "[*] mp42aac finished (exit code ignored)."

# Step 3: Collect ASAN/UBSAN output from log files
echo "" >> "$RESULT"
echo "=== ASAN/UBSAN LOG OUTPUT ===" >> "$RESULT"

found=0
for logfile in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "$logfile" ]; then
        echo "--- $logfile ---" >> "$RESULT"
        cat "$logfile" >> "$RESULT"
        found=1
    fi
done

if [ "$found" -eq 0 ]; then
    echo "(no asan log files found)" >> "$RESULT"
fi

echo "[*] Results written to $RESULT"

# Quick summary to stdout
echo ""
echo "=== SUMMARY ==="
if grep -qE "(ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:|SUMMARY: AddressSanitizer|heap-buffer-overflow|heap-use-after-free|stack-buffer-overflow|SEGV|bad_alloc)" "$RESULT" 2>/dev/null; then
    echo "SANITIZER ERROR DETECTED"
else
    echo "No sanitizer error found in result output"
fi

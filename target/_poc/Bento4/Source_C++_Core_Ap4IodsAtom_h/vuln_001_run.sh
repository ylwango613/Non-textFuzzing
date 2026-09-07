#!/bin/bash
set -e

SCRIPT_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IodsAtom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
POC_FILE="$SCRIPT_DIR/vuln_001.mp4"
RESULT_FILE="$SCRIPT_DIR/vuln_001_result.txt"
ASAN_LOG="$SCRIPT_DIR/asan_001.log"

echo "=== VULN 001 Run Script ===" > "$RESULT_FILE"
echo "Date: $(date)" >> "$RESULT_FILE"
echo "" >> "$RESULT_FILE"

# Step 1: Generate the PoC file
echo "[*] Generating PoC file..." | tee -a "$RESULT_FILE"
python3 "$SCRIPT_DIR/vuln_001_gen.py" 2>&1 | tee -a "$RESULT_FILE"
echo "" >> "$RESULT_FILE"

# Step 2: Run with ASAN/UBSAN
echo "[*] Running mp42aac with ASAN+UBSAN..." | tee -a "$RESULT_FILE"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BINARY" "$POC_FILE" /dev/null \
  >> "$RESULT_FILE" 2>&1 || true

echo "" >> "$RESULT_FILE"

# Step 3: Collect ASAN/UBSAN logs
echo "[*] Collecting sanitizer logs..." >> "$RESULT_FILE"
found_asan=0
for f in "${ASAN_LOG}".*; do
    if [ -f "$f" ]; then
        echo "--- ASAN log: $f ---" >> "$RESULT_FILE"
        cat "$f" >> "$RESULT_FILE"
        found_asan=1
    fi
done
if [ "$found_asan" -eq 0 ]; then
    # Also check if ASAN wrote to stderr directly (already in result)
    echo "(no separate ASAN log files found; output above may contain inline reports)" >> "$RESULT_FILE"
fi

echo "" >> "$RESULT_FILE"
echo "=== Done ===" >> "$RESULT_FILE"

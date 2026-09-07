#!/bin/bash
# VULN-001 PoC runner: Integer Overflow in AP4_Array::EnsureCapacity (Bento4)

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Array_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_001.mp4"
OUTPUT_TXT="$POC_DIR/vuln_001_result.txt"
ASAN_LOG="$POC_DIR/asan_001.log"

cd "$POC_DIR" || exit 1

# Step 1: Generate the crafted MP4
echo "[*] Generating vuln_001.mp4 ..."
python3 "$POC_DIR/vuln_001_gen.py"

# Step 2: Run mp42aac with ASAN logging
echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
    "$BINARY" \
    "$INPUT" \
    /dev/null \
    > "$OUTPUT_TXT" 2>&1 || true

echo "[*] mp42aac exit code captured (errors expected)"

# Step 3: Grep ASAN/UBSAN errors from log files and append
echo "" >> "$OUTPUT_TXT"
echo "=== ASAN/UBSAN Log Output ===" >> "$OUTPUT_TXT"
for logfile in "${ASAN_LOG}".*; do
    if [ -f "$logfile" ]; then
        echo "--- $logfile ---" >> "$OUTPUT_TXT"
        cat "$logfile" >> "$OUTPUT_TXT"
    fi
done

# Also check if there are any asan logs without PID suffix
if [ -f "$ASAN_LOG" ]; then
    echo "--- $ASAN_LOG ---" >> "$OUTPUT_TXT"
    cat "$ASAN_LOG" >> "$OUTPUT_TXT"
fi

echo "[*] Done. Results in $OUTPUT_TXT"
cat "$OUTPUT_TXT"

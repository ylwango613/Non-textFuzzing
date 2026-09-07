#!/bin/bash
# Run script for VULN-002: AP4_ObjectDescriptor SubStream Integer Underflow
# Generates the PoC MP4 then runs the ASAN+UBSAN binary against it.

set -e

SCRIPT_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IodsAtom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
POC_MP4="$SCRIPT_DIR/vuln_002.mp4"
RESULT_FILE="$SCRIPT_DIR/vuln_002_result.txt"
ASAN_LOG_PREFIX="$SCRIPT_DIR/asan_002.log"

echo "=== VULN-002 PoC Runner ===" | tee "$RESULT_FILE"
echo "Date: $(date)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Step 1: generate the crafted MP4
echo "[*] Generating crafted MP4..." | tee -a "$RESULT_FILE"
python3 "$SCRIPT_DIR/vuln_002_gen.py" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

if [ ! -f "$POC_MP4" ]; then
    echo "[!] Failed to generate MP4" | tee -a "$RESULT_FILE"
    exit 1
fi

# Step 2: run the ASAN+UBSAN binary
echo "[*] Running mp42aac with ASAN+UBSAN..." | tee -a "$RESULT_FILE"
echo "[*] Binary: $BINARY" | tee -a "$RESULT_FILE"
echo "[*] Input:  $POC_MP4" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
UBSAN_OPTIONS="print_stacktrace=1:log_path=${ASAN_LOG_PREFIX}" \
    "$BINARY" "$POC_MP4" /dev/null \
    >> "$RESULT_FILE" 2>&1 || true

echo "" | tee -a "$RESULT_FILE"

# Step 3: collect any ASAN/UBSAN log files
echo "[*] Collecting sanitizer log files..." | tee -a "$RESULT_FILE"
FOUND_SANITIZER=0
for f in "${ASAN_LOG_PREFIX}."*; do
    if [ -f "$f" ]; then
        echo "--- Found log: $f ---" | tee -a "$RESULT_FILE"
        cat "$f" | tee -a "$RESULT_FILE"
        FOUND_SANITIZER=1
    fi
done

if [ "$FOUND_SANITIZER" -eq 0 ]; then
    echo "[*] No separate sanitizer log files found." | tee -a "$RESULT_FILE"
fi

echo "" | tee -a "$RESULT_FILE"
echo "=== Done ===" | tee -a "$RESULT_FILE"

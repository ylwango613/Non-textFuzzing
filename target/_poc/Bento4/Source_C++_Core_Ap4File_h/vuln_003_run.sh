#!/bin/bash
# Run PoC for VULN 003: stsz atom incorrect overflow guard
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4File_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4_FILE="${POC_DIR}/vuln_003.mp4"
RESULT_FILE="${POC_DIR}/vuln_003_result.txt"
ASAN_LOG="${POC_DIR}/asan_003.log"

cd "$POC_DIR" || exit 1

echo "[1] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_003_gen.py"
if [ $? -ne 0 ]; then
    echo "ERROR: Python script failed" | tee "$RESULT_FILE"
    exit 1
fi

echo "[2] Running mp42aac with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}:detect_leaks=0" \
    "$BINARY" "$MP4_FILE" /dev/null \
    > "$RESULT_FILE" 2>&1 || true

# Append any ASAN log files
for f in "${POC_DIR}"/asan_003.log.*; do
    if [ -f "$f" ]; then
        echo "" >> "$RESULT_FILE"
        echo "=== ASAN LOG: $f ===" >> "$RESULT_FILE"
        cat "$f" >> "$RESULT_FILE"
    fi
done

echo "" >> "$RESULT_FILE"
echo "=== EXIT ===" >> "$RESULT_FILE"

echo "[3] Result:"
cat "$RESULT_FILE"

#!/bin/bash

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FileCopier_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_001.mp4"
OUTPUT="/tmp/vuln_001_out.aac"
RESULT_FILE="${POC_DIR}/vuln_001_result.txt"
STATUS_FILE="${POC_DIR}/vuln_001_status.txt"

# Step 1: Generate the malicious MP4
echo "[*] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_001_gen.py"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate MP4" | tee -a "${RESULT_FILE}"
    echo "ERROR" > "${STATUS_FILE}"
    exit 1
fi
echo "[*] MP4 generated: ${INPUT}"

# Step 2: Run mp42aac with ASAN/UBSAN options
echo "[*] Running mp42aac on malicious input..."
export ASAN_OPTIONS="detect_odr_violation=0:abort_on_error=0:halt_on_error=0:print_stacktrace=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0"

RUN_OUTPUT=$("${BINARY}" "${INPUT}" "${OUTPUT}" 2>&1)
EXIT_CODE=$?

echo "[*] Exit code: ${EXIT_CODE}"
echo "[*] Binary output:"
echo "${RUN_OUTPUT}"

# Step 3: Log results
{
    echo "=== vuln_001 run results ==="
    echo "Timestamp: $(date)"
    echo "Exit code: ${EXIT_CODE}"
    echo "--- Output ---"
    echo "${RUN_OUTPUT}"
    echo "--- End Output ---"
} >> "${RESULT_FILE}"

# Step 4: Detect crash / sanitizer errors
if echo "${RUN_OUTPUT}" | grep -qE "ERROR: AddressSanitizer|heap-buffer-overflow|SEGV|stack-buffer-overflow|heap-use-after-free|runtime error|UndefinedBehaviorSanitizer"; then
    echo "[!] CRASH / SANITIZER ERROR DETECTED"
    echo "VERIFIED_CRASH" > "${STATUS_FILE}"
    echo "Sanitizer findings:" >> "${RESULT_FILE}"
    echo "${RUN_OUTPUT}" | grep -E "ERROR:|runtime error:|SUMMARY:" >> "${RESULT_FILE}"
elif [ ${EXIT_CODE} -ne 0 ]; then
    echo "[!] Non-zero exit code but no recognizable sanitizer output"
    echo "UNVERIFIED" > "${STATUS_FILE}"
else
    echo "[*] No crash detected"
    echo "UNVERIFIED" > "${STATUS_FILE}"
fi

echo "[*] Status written to ${STATUS_FILE}"
cat "${STATUS_FILE}"

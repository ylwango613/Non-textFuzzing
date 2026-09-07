#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Descriptor_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_001.mp4"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"

# Step 1: Generate the malicious MP4 file
echo "[*] Generating malicious MP4 input ..."
python3 "${POC_DIR}/vuln_001_gen.py"

# Step 2: Run mp42aac with ASAN
echo "[*] Running mp42aac with ASAN ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
    "${BINARY}" \
    "${INPUT}" \
    /dev/null \
    > "${RESULT}" 2>&1 || true

# Step 3: Collect any ASAN / UBSAN output from log files
echo "[*] Checking for ASAN/UBSAN reports ..."
shopt -s nullglob
for log in "${ASAN_LOG_PREFIX}."*; do
    echo "--- ASAN/UBSAN log: ${log} ---" >> "${RESULT}"
    cat "${log}" >> "${RESULT}"
done
shopt -u nullglob

echo "[*] Done. Result written to: ${RESULT}"

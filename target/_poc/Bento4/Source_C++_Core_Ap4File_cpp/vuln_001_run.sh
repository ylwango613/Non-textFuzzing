#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4File_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4_FILE="${POC_DIR}/vuln_001.mp4"
RESULT_FILE="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_BASE="${POC_DIR}/asan.log"

# Clean up previous run
rm -f "${RESULT_FILE}" "${ASAN_LOG_BASE}".*

# Step 1: generate the malicious MP4
echo "[*] Generating malicious MP4..."
python3 "${POC_DIR}/vuln_001_gen.py"

# Step 2: run the binary under ASAN
echo "[*] Running binary..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}" \
    "${BINARY}" "${MP4_FILE}" /dev/null \
    > "${RESULT_FILE}" 2>&1 || true

# Step 3: append any ASAN log files
for f in "${ASAN_LOG_BASE}".*; do
    [ -f "$f" ] && cat "$f" >> "${RESULT_FILE}"
done

echo "[*] Done. Results in ${RESULT_FILE}"

#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_h"
MP4="${POC_DIR}/vuln_003.mp4"
RESULT="${POC_DIR}/vuln_003_result.txt"
ASAN_LOG_BASE="${POC_DIR}/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "[*] Step 1: Generating malicious MP4..." | tee "${RESULT}"
python3 "${POC_DIR}/vuln_003_gen.py" | tee -a "${RESULT}"

echo "" | tee -a "${RESULT}"
echo "[*] Step 2: Running mp42aac under ASAN..." | tee -a "${RESULT}"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}" \
  "${BINARY}" \
  "${MP4}" \
  /dev/null \
  >> "${RESULT}" 2>&1 || true

echo "" | tee -a "${RESULT}"
echo "[*] Step 3: Checking for ASAN/UBSAN logs..." | tee -a "${RESULT}"

# Append any ASAN/UBSAN error logs
for f in "${ASAN_LOG_BASE}."*; do
    if [ -f "${f}" ]; then
        echo "--- ASAN log: ${f} ---" | tee -a "${RESULT}"
        cat "${f}" | tee -a "${RESULT}"
    fi
done

echo "" | tee -a "${RESULT}"
echo "[*] Done. Full output in ${RESULT}"

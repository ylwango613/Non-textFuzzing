#!/bin/bash
# PoC runner for VULN 002 — AP4_CttsAtom Integer Overflow -> Heap Buffer Over-read
set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_cpp"
MP4_FILE="${POC_DIR}/vuln_002.mp4"
RESULT_FILE="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# Step 1: Generate the malicious MP4
echo "[*] Generating vuln_002.mp4 ..."
python3 "${POC_DIR}/vuln_002_gen.py"

# Step 2: Run mp42aac under ASAN
echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "${BINARY}" \
  "${MP4_FILE}" \
  /dev/null \
  > "${RESULT_FILE}" 2>&1 || true

# Step 3: Append any ASAN/UBSAN log output to result file
echo "" >> "${RESULT_FILE}"
echo "=== ASAN/UBSAN LOG ===" >> "${RESULT_FILE}"
for logfile in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "$logfile" ]; then
        echo "--- ${logfile} ---" >> "${RESULT_FILE}"
        cat "$logfile" >> "${RESULT_FILE}"
    fi
done

echo "[*] Done. Results in ${RESULT_FILE}"

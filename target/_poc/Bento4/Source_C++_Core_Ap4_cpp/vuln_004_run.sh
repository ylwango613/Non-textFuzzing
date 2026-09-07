#!/usr/bin/env bash
# PoC runner for VULN 004 — AP4_SaioAtom Bounds-Check Integer Overflow
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_cpp"
INPUT="${POC_DIR}/vuln_004.mp4"
RESULT="${POC_DIR}/vuln_004_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "[*] Step 1: Generating malicious MP4..."
python3 "${POC_DIR}/vuln_004_gen.py"

echo "[*] Step 2: Running mp42aac against malicious input..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
  "${BINARY}" \
  "${INPUT}" \
  /dev/null \
  > "${RESULT}" 2>&1 || true

echo "[*] Step 3: Appending ASAN/UBSAN logs to result..."
for log in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "${log}" ]; then
        echo "" >> "${RESULT}"
        echo "=== ASAN/UBSAN log: ${log} ===" >> "${RESULT}"
        cat "${log}" >> "${RESULT}"
    fi
done

echo "[*] Done. Results in: ${RESULT}"

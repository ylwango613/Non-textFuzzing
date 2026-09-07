#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_004.mp4"
RESULT="${POC_DIR}/vuln_004_result.txt"
ASAN_LOG="${POC_DIR}/asan.log"

echo "[*] Step 1: Generating malicious MP4..."
python3 "${POC_DIR}/vuln_004_gen.py"

echo "[*] Step 2: Running mp42aac with malicious input..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "${BINARY}" \
  "${INPUT}" \
  /dev/null \
  > "${RESULT}" 2>&1 || true

echo "[*] Step 3: Appending ASAN/UBSAN output..."
for f in "${ASAN_LOG}".*; do
    if [ -f "$f" ]; then
        echo "=== ASAN log: $f ===" >> "${RESULT}"
        cat "$f" >> "${RESULT}"
    fi
done

echo "[*] Done. Result saved to ${RESULT}"
cat "${RESULT}"

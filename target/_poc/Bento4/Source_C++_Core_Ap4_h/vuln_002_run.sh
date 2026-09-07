#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_h"
MP4="${POC_DIR}/vuln_002.mp4"
RESULT="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG="${POC_DIR}/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "[*] Step 1: Generating malicious MP4..."
python3 "${POC_DIR}/vuln_002_gen.py"

echo "[*] Step 2: Running mp42aac with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "${BINARY}" \
  "${MP4}" \
  /dev/null \
  > "${RESULT}" 2>&1 || true

echo "[*] Step 3: Collecting ASAN/UBSAN output..."
for f in "${ASAN_LOG}".*; do
    if [ -f "$f" ]; then
        echo "=== ASAN log: $f ===" >> "${RESULT}"
        cat "$f" >> "${RESULT}"
    fi
done

echo "[*] Done. Result written to ${RESULT}"

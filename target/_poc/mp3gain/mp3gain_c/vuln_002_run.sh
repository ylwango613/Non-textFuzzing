#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/mp3gain/mp3gain_c"

[ -f vuln_002.mp3 ] || python3 vuln_002_gen.py

# Remove stale ASAN logs
rm -f ./asan.log.*

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain vuln_002.mp3 \
  > vuln_002_result.txt 2>&1 || true

for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_002_result.txt || true
done

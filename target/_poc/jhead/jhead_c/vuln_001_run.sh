#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/jhead/jhead_c"
[ -f vuln_001_input.webp ] || python3 vuln_001_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/jhead/build_test/jhead vuln_001_input.webp > vuln_001_result.txt 2>&1 || true
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_001_result.txt || true
done

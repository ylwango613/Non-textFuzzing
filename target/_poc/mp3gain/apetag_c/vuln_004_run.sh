#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/mp3gain/apetag_c"
[ -f vuln_004.mp3 ] || python3 vuln_004_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain vuln_004.mp3 \
  > vuln_004_result.txt 2>&1 || true
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:|allocation-size-too-large|SEGV" "$f" \
    >> vuln_004_result.txt || true
done

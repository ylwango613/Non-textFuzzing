#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/mp3gain/apetag_c"
[ -f vuln_003.mp3 ] || python3 vuln_003_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain vuln_003.mp3 \
  > vuln_003_result.txt 2>&1 || true
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_003_result.txt || true
done

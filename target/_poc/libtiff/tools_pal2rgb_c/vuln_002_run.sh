#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/tools_pal2rgb_c"

[ -f vuln_002.tif ] || python3 vuln_002_gen.py

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/pal2rgb \
  vuln_002.tif /tmp/pal2rgb_out_002.tif \
  > vuln_002_result.txt 2>&1 || true

for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_002_result.txt || true
done

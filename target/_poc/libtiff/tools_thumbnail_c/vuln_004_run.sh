#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/tools_thumbnail_c"

[ -f vuln_004.tif ] || python3 vuln_004_gen.py

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/thumbnail vuln_004.tif /tmp/thumbnail_out_004.tif > vuln_004_result.txt 2>&1 || true

for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_004_result.txt || true
done

#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_packbits_c"
[ -f vuln_001.tif ] || python3 vuln_001_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit vuln_001.tif /tmp/tiffsplit_out_001_ > vuln_001_result.txt 2>&1 || true
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_001_result.txt || true
done

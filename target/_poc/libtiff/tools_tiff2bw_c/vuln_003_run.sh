#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/libtiff/tools_tiff2bw_c"
[ -f vuln_003.tif ] || python3 vuln_003_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiff2bw vuln_003.tif /tmp/tiff2bw_out_003.tif > vuln_003_result.txt 2>&1 || true
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_003_result.txt || true
done

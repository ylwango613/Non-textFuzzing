#!/bin/bash
set -e
cd /data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_jasper_c

python3 vuln_001_gen.py

ASAN_OPTIONS="abort_on_error=0:log_path=/data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_jasper_c/asan.log" \
  /data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo \
  -f /data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_jasper_c/vuln_001.jp2 \
  > /data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_jasper_c/vuln_001_result.txt 2>&1 || true

for f in /data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_jasper_c/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> /data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_jasper_c/vuln_001_result.txt
done

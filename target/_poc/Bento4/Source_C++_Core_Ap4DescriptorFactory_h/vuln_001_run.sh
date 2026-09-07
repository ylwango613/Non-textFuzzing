#!/bin/bash
set -e
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4DescriptorFactory_h"
cd "$POC_DIR"

python3 "$POC_DIR/vuln_001_gen.py"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_001.log" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  "$POC_DIR/vuln_001.mp4" /dev/null \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

# Collect ASAN/UBSAN output
for f in "$POC_DIR"/asan_001.log.*; do
  [ -f "$f" ] && cat "$f" >> "$POC_DIR/vuln_001_result.txt" || true
done

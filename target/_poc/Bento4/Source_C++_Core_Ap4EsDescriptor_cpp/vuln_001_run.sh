#!/bin/bash
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4EsDescriptor_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

python3 "$POC_DIR/vuln_001_gen.py"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$BINARY" "$POC_DIR/vuln_001.mp4" /dev/null \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$POC_DIR/vuln_001_result.txt"
done

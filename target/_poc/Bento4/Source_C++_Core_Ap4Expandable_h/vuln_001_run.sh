#!/bin/bash
set -e
DIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Expandable_h
python3 "$DIR/vuln_001_gen.py"
ASAN_OPTIONS="abort_on_error=0:log_path=$DIR/asan.log" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  "$DIR/vuln_001.mp4" /dev/null \
  > "$DIR/vuln_001_result.txt" 2>&1 || true
# collect ASAN/UBSAN output
for f in "$DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$DIR/vuln_001_result.txt"
done

#!/bin/bash
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomSampleTable_cpp"
python3 "$POC_DIR/vuln_002_gen.py"
ASAN_OPTIONS="abort_on_error=0:hard_rss_limit_mb=512:log_path=$POC_DIR/asan.log" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  "$POC_DIR/vuln_002.mp4" /dev/null \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true
for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$POC_DIR/vuln_002_result.txt"
done

#!/bin/bash
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_h"
python3 "$POC_DIR/vuln_005_gen.py"
# Use hard_rss_limit_mb=1024 to quickly trigger OOM crash from unbounded allocation
# (system has 1TB RAM; without limit, the 16GB+ alloc would succeed slowly)
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log:hard_rss_limit_mb=1024" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  "$POC_DIR/vuln_005.mp4" /dev/null \
  > "$POC_DIR/vuln_005_result.txt" 2>&1 || true
for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$POC_DIR/vuln_005_result.txt" || true
done
echo "Done" >> "$POC_DIR/vuln_005_result.txt"

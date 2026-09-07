#!/bin/bash
set -e
POC_DIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4CommonEncryption_h

python3 "$POC_DIR/vuln_002_gen.py"

# max_allocation_size_mb=128 makes ASAN reject the ~4GB allocation (0xFFFFFFFC bytes)
# that results from the integer underflow in AP4_CencSampleEncryption constructor.
# Without this flag, Linux's memory overcommit allows the huge mmap to succeed silently.
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log:max_allocation_size_mb=128" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  "$POC_DIR/vuln_002.mp4" \
  /dev/null \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true

for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && grep -E "ERROR|runtime error|SUMMARY|bad_alloc|terminate|allocation-size-too-big|ABORTING" "$f" >> "$POC_DIR/vuln_002_result.txt" || true
done

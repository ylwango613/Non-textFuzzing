#!/bin/bash
set -e
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Co64Atom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

cd "$POC_DIR"
python3 "$POC_DIR/vuln_001_gen.py"

# mmap_limit_mb=512 caps ASAN's internal allocator at 512 MB.
# new AP4_UI64[0x1FFFFFFF] (== ~4 GB) exceeds that limit,
# triggering ASAN CHECK failure: (total_mmaped >> 20) < mmap_limit_mb
# Benign inputs produce no ASAN log; only the malicious input crashes here.
ASAN_OPTIONS="abort_on_error=0:mmap_limit_mb=512:allocator_may_return_null=0:log_path=$POC_DIR/asan.log" \
  "$BINARY" "$POC_DIR/vuln_001.mp4" /dev/null \
  > "$POC_DIR/vuln_001_result.txt" 2>&1 || true

# collect ASAN/UBSAN output
for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$POC_DIR/vuln_001_result.txt" && echo "[ASAN log: $f]" >> "$POC_DIR/vuln_001_result.txt"
done

echo "=== Done ===" >> "$POC_DIR/vuln_001_result.txt"

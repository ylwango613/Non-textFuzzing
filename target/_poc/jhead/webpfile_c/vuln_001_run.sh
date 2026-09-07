#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/jhead/webpfile_c"
[ -f vuln_001_input.jpg ] || python3 vuln_001_gen.py

# Use max_allocation_size_mb=512 so that malloc(0x80000000)=2048MB exceeds the
# limit and the ASAN allocator returns NULL (with allocator_may_return_null=1),
# causing fread(NULL, 1, ReadLen, infile) -> SIGSEGV (CWE-476).
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:allocator_may_return_null=1:max_allocation_size_mb=512" \
  /data/ylwang/non-textfuzz/target/jhead/build_test/jhead vuln_001_input.jpg > vuln_001_result.txt 2>&1 || true
for f in ./asan.log.*; do
  [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
    >> vuln_001_result.txt || true
done

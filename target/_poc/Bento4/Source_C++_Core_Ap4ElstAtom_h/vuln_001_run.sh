#!/bin/bash
set -e
cd /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_h

python3 vuln_001_gen.py

# Limit virtual memory to 2GB to force std::bad_alloc when the binary
# attempts to allocate ~80GB for the 0xFFFFFF00 * 20-byte elst entries.
# Without this limit, the allocation may succeed on large-memory machines
# (the system here has ~1TB RAM), causing a hang instead of a crash.
(
  ulimit -v $((2 * 1024 * 1024))  # 2GB virtual memory cap
  ASAN_OPTIONS="abort_on_error=0:log_path=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_h/asan.log" \
    /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
    /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_h/vuln_001.mp4 \
    /dev/null
) > /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_h/vuln_001_result.txt 2>&1 || true

# grep ASAN/UBSAN errors from log files
for f in /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_h/asan.log.*; do
  [ -f "$f" ] && grep -E "ERROR|SUMMARY|runtime error" "$f" >> /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_h/vuln_001_result.txt 2>/dev/null || true
done

#!/bin/bash
cd /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_h/
python3 vuln_001_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_h/asan.log" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_h/vuln_001.mp4 \
  /dev/null \
  > /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_h/vuln_001_result.txt 2>&1 || true
# Collect ASAN/UBSAN output
for f in /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_h/asan.log.*; do
  [ -f "$f" ] && grep -a -E "(ERROR|WARNING|SUMMARY|runtime error|AddressSanitizer|UndefinedBehaviorSanitizer)" "$f" >> /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_h/vuln_001_result.txt 2>/dev/null || true
done
echo "=== result.txt ===" && cat /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_h/vuln_001_result.txt

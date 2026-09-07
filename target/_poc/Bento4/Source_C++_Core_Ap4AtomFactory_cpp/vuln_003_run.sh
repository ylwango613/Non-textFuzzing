#!/bin/bash
POCDIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_cpp
python3 $POCDIR/vuln_003_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=$POCDIR/asan.log" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  $POCDIR/vuln_003.mp4 /dev/null \
  > $POCDIR/vuln_003_result.txt 2>&1 || true
for f in $POCDIR/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> $POCDIR/vuln_003_result.txt || true
done

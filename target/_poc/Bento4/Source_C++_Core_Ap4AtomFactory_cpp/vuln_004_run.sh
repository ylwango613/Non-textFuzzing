#!/bin/bash
POCDIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_cpp
python3 $POCDIR/vuln_004_gen.py
# hard_rss_limit_mb=8192: ensure crash even on hosts with >28 GB RAM (OOM abort when RSS>8 GB)
ASAN_OPTIONS="abort_on_error=0:log_path=$POCDIR/asan.log:hard_rss_limit_mb=8192" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  $POCDIR/vuln_004.mp4 /dev/null \
  > $POCDIR/vuln_004_result.txt 2>&1 || true
for f in $POCDIR/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> $POCDIR/vuln_004_result.txt || true
done

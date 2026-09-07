#!/bin/bash
# PoC runner — VULN 005 (AP4_SaizAtom unsigned underflow → OOM)

POCDIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_cpp
BINARY=/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac

python3 "$POCDIR/vuln_005_gen.py"

ASAN_OPTIONS="abort_on_error=0:log_path=$POCDIR/asan.log" \
    "$BINARY" "$POCDIR/vuln_005.mp4" /dev/null \
    > "$POCDIR/vuln_005_result.txt" 2>&1 || true

for f in "$POCDIR"/asan.log.*; do
    [ -f "$f" ] && cat "$f" >> "$POCDIR/vuln_005_result.txt" || true
done

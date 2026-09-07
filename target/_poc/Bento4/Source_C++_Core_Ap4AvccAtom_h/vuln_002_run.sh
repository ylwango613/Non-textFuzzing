#!/bin/bash
# VULN 002 - CWE-125 OOB Heap Read in AP4_AvccAtom::Create()
# Run PoC generator then execute mp42aac under ASAN.

set -euo pipefail

POCDIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AvccAtom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
RESULT="$POCDIR/vuln_002_result.txt"

# 1. Generate the malicious MP4
echo "[*] Generating vuln_002.mp4 ..."
python3 "$POCDIR/vuln_002_gen.py"

# 2. Run mp42aac under ASAN/UBSAN
echo "[*] Running mp42aac ..."
rm -f "$POCDIR"/asan.log.*
ASAN_OPTIONS="abort_on_error=0:log_path=$POCDIR/asan.log:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1" \
  "$BINARY" "$POCDIR/vuln_002.mp4" /dev/null \
  > "$RESULT" 2>&1 || true

# 3. Append all ASAN log files
for f in "$POCDIR"/asan.log.*; do
    [ -f "$f" ] && cat "$f" >> "$RESULT"
done

echo "[*] Done. Results in $RESULT"
cat "$RESULT"

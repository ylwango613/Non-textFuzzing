#!/bin/bash
# VULN 001 - AP4_AvccAtom::Create() OOB Heap Read
# Generates the PoC MP4 and runs it under the ASAN+UBSAN build of mp42aac.

POCDIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AvccAtom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
RESULT="$POCDIR/vuln_001_result.txt"

# Generate the malicious MP4
echo "[*] Generating vuln_001.mp4 ..."
python3 "$POCDIR/vuln_001_gen.py"

# Clear previous results
> "$RESULT"

echo "[*] Running mp42aac under ASAN ..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POCDIR/asan.log:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BINARY" "$POCDIR/vuln_001.mp4" /dev/null \
  >> "$RESULT" 2>&1 || true

# Append any ASAN log files
for f in "$POCDIR"/asan.log.*; do
    [ -f "$f" ] && cat "$f" >> "$RESULT"
done

echo "[*] Result summary:"
grep -E "ERROR:|SUMMARY:|heap-buffer-overflow|AddressSanitizer|stack-buffer|use-after-free|SEGV" \
    "$RESULT" | head -20 || echo "  (no ASAN markers found)"

echo "[*] Full result: $RESULT"

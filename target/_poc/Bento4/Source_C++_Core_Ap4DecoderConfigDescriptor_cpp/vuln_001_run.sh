#!/bin/bash
set -euo pipefail

POCDIR=/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4DecoderConfigDescriptor_cpp
BIN=/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac

# Step 1: Generate the malicious MP4
python3 "$POCDIR/vuln_001_gen.py"

# Step 2: Run mp42aac under ASAN/UBSAN
ASAN_OPTIONS="abort_on_error=0:detect_leaks=0:log_path=$POCDIR/asan.log" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=$POCDIR/ubsan.log" \
  "$BIN" "$POCDIR/vuln_001.mp4" /dev/null \
  > "$POCDIR/vuln_001_result.txt" 2>&1 || true

# Step 3: Append any ASAN/UBSAN log files
for f in "$POCDIR"/asan.log.* "$POCDIR"/ubsan.log.*; do
  [ -f "$f" ] && echo "=== SANITIZER LOG: $f ===" >> "$POCDIR/vuln_001_result.txt" && cat "$f" >> "$POCDIR/vuln_001_result.txt"
done

echo "[+] Done. See $POCDIR/vuln_001_result.txt"

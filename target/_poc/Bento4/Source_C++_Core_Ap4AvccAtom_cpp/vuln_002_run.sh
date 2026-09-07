#!/bin/bash
set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AvccAtom_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

python3 "$POC_DIR/vuln_002_gen.py"

ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$BINARY" "$POC_DIR/vuln_002.mp4" /dev/null \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true

# Collect ASAN output
for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && cat "$f" >> "$POC_DIR/vuln_002_result.txt" || true
done

echo "=== Result ===" >> "$POC_DIR/vuln_002_result.txt"
if grep -qE "heap-buffer-overflow|AddressSanitizer|SEGV|runtime error" "$POC_DIR/vuln_002_result.txt"; then
  echo "CRASH/SANITIZER ERROR DETECTED" >> "$POC_DIR/vuln_002_result.txt"
else
  echo "No sanitizer error detected" >> "$POC_DIR/vuln_002_result.txt"
fi

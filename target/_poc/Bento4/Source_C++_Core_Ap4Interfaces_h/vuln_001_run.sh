#!/bin/bash
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Interfaces_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# Step 1: Generate the malicious MP4
python3 "$POC_DIR/vuln_001_gen.py"

# Step 2: Run mp42aac with ASAN options; inner timeout=20s to catch hangs
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_001.log" \
  timeout 20 "$BINARY" "$POC_DIR/vuln_001.mp4" /dev/null \
  > "$POC_DIR/vuln_001_result.txt" 2>&1
BINARY_EXIT=$?

echo "mp42aac exit code: $BINARY_EXIT" >> "$POC_DIR/vuln_001_result.txt"

# exit 124 from timeout means the process was killed after the time limit (DoS hang)
if [ "$BINARY_EXIT" -eq 124 ]; then
  echo "CRASH_INDICATOR: process did not terminate within 20s (DoS / allocation hang)" \
    >> "$POC_DIR/vuln_001_result.txt"
fi

# Step 3: Append ASAN/UBSAN findings
for f in "$POC_DIR"/asan_001.log.*; do
  [ -f "$f" ] && grep -E "ERROR|SUMMARY|runtime error|AddressSanitizer|UndefinedBehavior" "$f" >> "$POC_DIR/vuln_001_result.txt" || true
done

echo "Done. Results in vuln_001_result.txt"

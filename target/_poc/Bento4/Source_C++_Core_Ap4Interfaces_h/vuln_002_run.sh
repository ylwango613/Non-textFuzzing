#!/bin/bash
set -e
POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Interfaces_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

# Step 1: Generate the malicious MP4
python3 "$POC_DIR/vuln_002_gen.py"

# Step 2: Run mp42aac with ASAN options
ASAN_OPTIONS="abort_on_error=0:hard_rss_limit_mb=512:log_path=$POC_DIR/asan_002.log" \
  "$BINARY" "$POC_DIR/vuln_002.mp4" /dev/null \
  > "$POC_DIR/vuln_002_result.txt" 2>&1 || true

# Step 3: Append ASAN/UBSAN findings
for f in "$POC_DIR"/asan_002.log.*; do
  [ -f "$f" ] && grep -E "ERROR|SUMMARY|runtime error|AddressSanitizer|UndefinedBehavior" "$f" >> "$POC_DIR/vuln_002_result.txt" || true
done

echo "Done. Results in vuln_002_result.txt"

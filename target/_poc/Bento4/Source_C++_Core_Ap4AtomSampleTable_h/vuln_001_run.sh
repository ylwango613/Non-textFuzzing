#!/bin/bash
set -e
POC_DIR='/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomSampleTable_h'
MP4="$POC_DIR/vuln_001.mp4"
RESULT="$POC_DIR/vuln_001_result.txt"
ASAN_LOG="$POC_DIR/asan.log"
BINARY='/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac'

python3 "$POC_DIR/vuln_001_gen.py"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "$BINARY" "$MP4" /dev/null > "$RESULT" 2>&1 || true

# Append any ASAN/UBSAN findings from log files
for f in "${ASAN_LOG}".*; do
  [ -f "$f" ] && grep -E 'ERROR|WARNING|runtime error' "$f" >> "$RESULT" 2>/dev/null || true
done
cat "$RESULT"

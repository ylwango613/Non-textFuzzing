#!/bin/bash
set -e
POC_DIR='/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomSampleTable_h'
MP4="$POC_DIR/vuln_002.mp4"
RESULT="$POC_DIR/vuln_002_result.txt"
ASAN_LOG="$POC_DIR/asan.log"
BINARY='/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac'

# Step 1: Generate the malicious MP4
python3 "$POC_DIR/vuln_002_gen.py"

# Step 2: Run mp42aac with ASAN options; allow non-zero exit
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "$BINARY" "$MP4" /dev/null > "$RESULT" 2>&1 || true

# Step 3: Append ASAN/UBSAN findings from log files
for f in "${ASAN_LOG}".*; do
  [ -f "$f" ] && cat "$f" >> "$RESULT" 2>/dev/null || true
done

# Step 4: Show results
echo "=== vuln_002_result.txt ==="
cat "$RESULT"

# Step 5: Check for crash indicators and set status
STATUS_FILE="$POC_DIR/vuln_002_status.txt"
if grep -qE 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)|heap-buffer-overflow|terminate called|bad_alloc|SIGSEGV|runtime error|stack-buffer-overflow|use-after-free' "$RESULT" 2>/dev/null; then
  echo "VERIFIED_CRASH" > "$STATUS_FILE"
  echo ""
  echo ">>> STATUS: VERIFIED_CRASH <<<"
elif grep -qE 'ERROR|FATAL|Sanitizer' "$RESULT" 2>/dev/null; then
  echo "VERIFIED_CRASH" > "$STATUS_FILE"
  echo ""
  echo ">>> STATUS: VERIFIED_CRASH (sanitizer error detected) <<<"
else
  echo "UNVERIFIED" > "$STATUS_FILE"
  echo ""
  echo ">>> STATUS: UNVERIFIED <<<"
fi

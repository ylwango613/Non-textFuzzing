#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="$POC_DIR/vuln_003.mp4"
RESULT="$POC_DIR/vuln_003_result.txt"
ASAN_LOG="$POC_DIR/asan.log"

# Step 1: Generate the malicious MP4
echo "[*] Generating vuln_003.mp4 ..."
python3 "$POC_DIR/vuln_003_gen.py"

# Step 2: Run mp42aac with the crafted file
echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=$ASAN_LOG" \
  "$BINARY" "$MP4" /dev/null \
  > "$RESULT" 2>&1 || true

echo "[*] mp42aac exited"

# Step 3: Append ASAN/UBSAN errors from asan.log.* to result.txt
for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && grep -E "ERROR:|runtime error:|SUMMARY:" "$f" >> "$RESULT" || true
done

echo "[*] Done. Results in $RESULT"

#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4File_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_003.mp4"
RESULT="$POC_DIR/vuln_003_result.txt"
ASAN_LOG="$POC_DIR/asan.log"

# Clean up previous results
rm -f "$RESULT" "$POC_DIR"/asan.log.*

# Step 1: Generate the malicious MP4
echo "[*] Generating malicious MP4..." | tee -a "$RESULT"
python3 "$POC_DIR/vuln_003_gen.py" 2>&1 | tee -a "$RESULT"

# Step 2: Run the binary with ASAN
echo "[*] Running binary against vuln_003.mp4..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=$ASAN_LOG" \
  "$BINARY" "$INPUT" /dev/null \
  >> "$RESULT" 2>&1 || true

# Step 3: Collect ASAN logs
for f in "$POC_DIR"/asan.log.*; do
    [ -f "$f" ] && cat "$f" >> "$RESULT"
done

echo "[*] Done. Results in $RESULT"

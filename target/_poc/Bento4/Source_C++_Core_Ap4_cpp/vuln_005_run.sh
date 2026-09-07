#!/bin/bash
# PoC runner for VULN 005 - AP4_TrunAtom Unchecked sample_count
set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_005.mp4"
RESULT="$POC_DIR/vuln_005_result.txt"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"

echo "[*] Step 1: Generating malicious MP4..."
python3 "$POC_DIR/vuln_005_gen.py"

echo "[*] Step 2: Running mp42aac with malicious input..."
ASAN_OPTIONS="abort_on_error=0:log_path=$ASAN_LOG_PREFIX" \
  "$BINARY" \
  "$INPUT" \
  /dev/null \
  > "$RESULT" 2>&1 || true

echo "[*] Step 3: Collecting ASAN/UBSAN output..."
for f in "$ASAN_LOG_PREFIX".*; do
  [ -f "$f" ] && grep -E "ERROR:|runtime error:|SUMMARY:" "$f" >> "$RESULT" || true
done

echo "[*] Done. Result written to $RESULT"
cat "$RESULT"

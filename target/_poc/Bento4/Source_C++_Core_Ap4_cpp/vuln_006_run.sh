#!/usr/bin/env bash
# VULN 006 PoC runner — AP4_TfraAtom Unchecked entry_count
set -e

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_cpp"
MP4="$POC_DIR/vuln_006.mp4"
RESULT="$POC_DIR/vuln_006_result.txt"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "[*] Generating malicious MP4 ..."
python3 "$POC_DIR/vuln_006_gen.py"

echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan.log" \
  "$BINARY" \
  "$MP4" \
  /dev/null \
  > "$RESULT" 2>&1 || true

echo "[*] Collecting ASAN/UBSAN log entries ..."
for f in "$POC_DIR"/asan.log.*; do
  [ -f "$f" ] && grep -E "ERROR:|runtime error:|SUMMARY:" "$f" >> "$RESULT" || true
done

echo "[*] Done. Results in $RESULT"
cat "$RESULT"

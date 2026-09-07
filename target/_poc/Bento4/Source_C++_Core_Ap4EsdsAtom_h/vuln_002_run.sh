#!/bin/bash
# PoC runner for VULN 002 - Integer Underflow in AP4_DecoderConfigDescriptor
set -e

SCRIPT_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4EsdsAtom_h"
MP42AAC="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4_FILE="$SCRIPT_DIR/vuln_002.mp4"
RESULT_FILE="$SCRIPT_DIR/vuln_002_result.txt"
ASAN_LOG="$SCRIPT_DIR/asan.log"

echo "[*] Generating malicious MP4..."
python3 "$SCRIPT_DIR/vuln_002_gen.py"

echo "[*] Running mp42aac with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "$MP42AAC" "$MP4_FILE" /dev/null \
  > "$RESULT_FILE" 2>&1 || true

# Collect any ASAN log shards
for f in "${ASAN_LOG}".*; do
    [ -f "$f" ] && cat "$f" >> "$RESULT_FILE" || true
done

echo "[*] Result:"
cat "$RESULT_FILE"
echo
echo "[*] Full result saved to: $RESULT_FILE"

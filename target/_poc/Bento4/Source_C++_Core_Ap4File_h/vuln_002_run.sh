#!/bin/bash
# VULN 002 runner: ctts integer overflow -> heap OOB / OOM in Bento4 mp42aac
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4File_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="${POC_DIR}/vuln_002.mp4"
RESULT="${POC_DIR}/vuln_002_result.txt"
ASAN_LOG="${POC_DIR}/asan_002.log"

cd "$POC_DIR"

echo "[*] Generating malicious MP4 ..."
python3 vuln_002_gen.py

echo "[*] Running mp42aac ..."
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "$BINARY" "$MP4" /dev/null \
  > "$RESULT" 2>&1 || true

# append any ASAN log files
for f in "${ASAN_LOG}".*; do
    [ -f "$f" ] && { echo "--- ASAN log: $f ---" >> "$RESULT"; cat "$f" >> "$RESULT"; }
done

echo "=== EXIT ===" >> "$RESULT"

echo "[*] Result:"
cat "$RESULT"

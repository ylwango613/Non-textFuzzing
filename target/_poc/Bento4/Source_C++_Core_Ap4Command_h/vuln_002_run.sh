#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Command_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="$POC_DIR/vuln_002.mp4"
RESULT="$POC_DIR/vuln_002_result.txt"
ASAN_LOG="$POC_DIR/asan.log"

echo "[*] Generating malicious MP4..." | tee "$RESULT"
python3 "$POC_DIR/vuln_002_gen.py" | tee -a "$RESULT"

echo "[*] Running mp42aac with ASAN..." | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
  "$BINARY" "$MP4" /dev/null \
  >> "$RESULT" 2>&1 || true

echo "[*] Collecting ASAN/UBSAN log output..." | tee -a "$RESULT"
for f in "${ASAN_LOG}".*; do
    [ -f "$f" ] || continue
    echo "--- $f ---" >> "$RESULT"
    grep -E "(ERROR|WARNING|runtime error|SUMMARY|heap|stack|global|READ|WRITE)" "$f" >> "$RESULT" 2>/dev/null || true
    cat "$f" >> "$RESULT" 2>/dev/null || true
done

echo "[*] Done. See $RESULT"

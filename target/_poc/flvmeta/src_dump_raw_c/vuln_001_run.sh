#!/bin/bash
set -euo pipefail
cd "/data/ylwang/non-textfuzz/target/_poc/flvmeta/src_dump_raw_c"

BINARY="/data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta"
FLV="vuln_001.flv"
RESULT="vuln_001_result.txt"

echo "[*] Generating crafted FLV file (20000-level nested AMF)..." | tee "$RESULT"
[ -f "$FLV" ] || python3 vuln_001_gen.py

echo "[*] Running flvmeta against $FLV ..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BINARY" "$FLV" >> "$RESULT" 2>&1 || true

echo "[*] Checking ASAN/UBSAN logs..." | tee -a "$RESULT"
for f in ./asan.log.*; do
  [ -f "$f" ] && {
    echo "=== $f ===" >> "$RESULT"
    cat "$f" >> "$RESULT"
  } || true
done

echo "[*] Done. Results in $RESULT"

# Summary check
if grep -qE "stack-overflow|SIGSEGV|signal 11|AddressSanitizer|runtime error:|ERROR:" "$RESULT" 2>/dev/null; then
  echo "[!] CRASH / ERROR DETECTED"
else
  echo "[~] No obvious crash indicators found"
fi

#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IproAtom_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
MP4="$POC_DIR/vuln_001.mp4"
RESULT="$POC_DIR/vuln_001_result.txt"
ASAN_LOG_BASE="$POC_DIR/asan.log"

echo "[*] Step 1: Generating malicious MP4..." | tee "$RESULT"
python3 "$POC_DIR/vuln_001_gen.py" 2>&1 | tee -a "$RESULT"

echo "" | tee -a "$RESULT"
echo "[*] Step 2: Running mp42aac under ASAN/UBSAN..." | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_BASE}" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BINARY" \
  "$MP4" \
  /dev/null \
  >> "$RESULT" 2>&1 || true

echo "" | tee -a "$RESULT"
echo "[*] Step 3: Checking for ASAN/UBSAN errors..." | tee -a "$RESULT"

# Grep asan.log.* files for sanitizer errors
FOUND_ERRORS=0
for log_file in "${ASAN_LOG_BASE}".*; do
    if [ -f "$log_file" ]; then
        echo "[+] Found ASAN log: $log_file" | tee -a "$RESULT"
        cat "$log_file" >> "$RESULT"
        FOUND_ERRORS=1
    fi
done

# Also check result.txt itself for inline UBSAN output (avoid matching program's own ERROR: lines)
if grep -qE "(runtime error:|AddressSanitizer:|UndefinedBehaviorSanitizer:|SUMMARY:.*Sanitizer|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|use-after-free|UBSAN:|ubsan:)" "$RESULT" 2>/dev/null; then
    FOUND_ERRORS=1
fi

if [ "$FOUND_ERRORS" -eq 1 ]; then
    echo "" | tee -a "$RESULT"
    echo "[!] ASAN/UBSAN errors detected!" | tee -a "$RESULT"
else
    echo "" | tee -a "$RESULT"
    echo "[-] No ASAN/UBSAN errors found in logs." | tee -a "$RESULT"
fi

echo "[*] Done. Results in: $RESULT"

#!/bin/bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Command_h"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_004.mp4"
RESULT="$POC_DIR/vuln_004_result.txt"
ASAN_LOG="$POC_DIR/asan.log"

echo "[*] Generating vuln_004.mp4 ..." | tee "$RESULT"
python3 "$POC_DIR/vuln_004_gen.py" | tee -a "$RESULT"

echo "" | tee -a "$RESULT"
echo "[*] Running mp42aac against crafted MP4 ..." | tee -a "$RESULT"
echo "[*] Binary: $BINARY" | tee -a "$RESULT"
echo "[*] Input:  $INPUT"  | tee -a "$RESULT"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG}" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$BINARY" "$INPUT" /dev/null \
  >> "$RESULT" 2>&1 || true

echo "" | tee -a "$RESULT"
echo "[*] Checking for sanitizer reports ..." | tee -a "$RESULT"

found_crash=0
for f in "${ASAN_LOG}."*; do
    if [ -f "$f" ]; then
        echo "[*] Sanitizer log: $f" | tee -a "$RESULT"
        cat "$f" | tee -a "$RESULT"
        grep -qE "ERROR|runtime error|SUMMARY" "$f" 2>/dev/null && found_crash=1 || true
    fi
done

# Also check if the result file itself contains error keywords
if grep -qE "ERROR: AddressSanitizer|ERROR: UndefinedBehavior|runtime error:" "$RESULT" 2>/dev/null; then
    found_crash=1
fi

echo "" | tee -a "$RESULT"
if [ "$found_crash" -eq 1 ]; then
    echo "[+] SANITIZER ERROR DETECTED" | tee -a "$RESULT"
    echo "VERIFIED_CRASH" > "$POC_DIR/vuln_004_status.txt"
else
    echo "[-] No sanitizer error detected (underflow may be silent with file-backed streams)" | tee -a "$RESULT"
    # Check if process exited abnormally
    echo "UNVERIFIED" > "$POC_DIR/vuln_004_status.txt"
fi

echo "[*] Status written to $POC_DIR/vuln_004_status.txt"
echo "[*] Full result in $RESULT"

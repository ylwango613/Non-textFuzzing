#!/usr/bin/env bash
set -euo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Apps_Mp42Aac_Mp42Aac_cpp"
MP4="$POC_DIR/vuln_002.mp4"
RESULT="$POC_DIR/vuln_002_result.txt"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"

echo "=== VULN-002 PoC run: $(date) ===" | tee "$RESULT"

# Step A: Generate the malicious MP4
echo "[*] Generating malicious MP4..." | tee -a "$RESULT"
python3 "$POC_DIR/vuln_002_gen.py" 2>&1 | tee -a "$RESULT"

# Step B: Run mp42aac with ASAN
echo "" | tee -a "$RESULT"
echo "[*] Running mp42aac under ASAN..." | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
    "$BINARY" "$MP4" /dev/null \
    >> "$RESULT" 2>&1 || true

# Step C: Grep ASAN/UBSAN errors from log files
echo "" | tee -a "$RESULT"
echo "[*] Checking ASAN/UBSAN log files..." | tee -a "$RESULT"
found_error=0
for logfile in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "$logfile" ]; then
        echo "--- $logfile ---" | tee -a "$RESULT"
        cat "$logfile" | tee -a "$RESULT"
        # Check for known error signatures
        if grep -qE "(ERROR: AddressSanitizer|SUMMARY:|heap-buffer-overflow|heap-use-after-free|undefined behaviour|runtime error|UBSan)" "$logfile" 2>/dev/null; then
            found_error=1
        fi
        echo "" | tee -a "$RESULT"
    fi
done

if [ "$found_error" -eq 1 ]; then
    echo "[!] ASAN/UBSAN error detected." | tee -a "$RESULT"
else
    echo "[-] No ASAN/UBSAN log files found or no errors detected." | tee -a "$RESULT"
fi

echo "" | tee -a "$RESULT"
echo "=== Done ===" | tee -a "$RESULT"

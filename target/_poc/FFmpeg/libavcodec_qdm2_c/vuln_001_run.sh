#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted MOV file..."
python3 vuln_001_gen.py

echo ""
echo "[*] Running ffmpeg on crafted input..."
echo "[*] Binary: $BIN"

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:detect_leaks=0" \
    "$BIN" -v verbose -i vuln_001_input.mov -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN logs
if ls asan.log.* 1>/dev/null 2>&1; then
    echo "" >> vuln_001_result.txt
    echo "=== ASAN LOG ===" >> vuln_001_result.txt
    cat asan.log.* >> vuln_001_result.txt
fi

echo "[*] Result saved to vuln_001_result.txt"
echo ""
echo "=== OUTPUT SUMMARY ==="
head -50 vuln_001_result.txt

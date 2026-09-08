#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted JPEG..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg on crafted input..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.jpg -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN logs
if ls asan.log.* 2>/dev/null | head -1 | grep -q .; then
    echo "--- ASAN OUTPUT ---" >> vuln_001_result.txt
    cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
fi

echo "[*] Done. Results in vuln_001_result.txt"
cat vuln_001_result.txt

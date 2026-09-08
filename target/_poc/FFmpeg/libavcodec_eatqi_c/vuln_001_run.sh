#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted input file..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.ea -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN log files
if ls asan.log.* 1>/dev/null 2>&1; then
    echo "--- ASAN LOG ---" >> vuln_001_result.txt
    cat asan.log.* >> vuln_001_result.txt
fi

echo "[*] Result written to vuln_001_result.txt"

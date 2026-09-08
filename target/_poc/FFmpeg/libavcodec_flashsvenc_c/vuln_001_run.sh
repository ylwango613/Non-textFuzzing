#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted AVI input..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg with flashsv encoder..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -y -i vuln_001_input.avi -vcodec flashsv -f flv /dev/null > vuln_001_result.txt 2>&1 || true

echo "[*] Collecting ASAN logs..."
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. See vuln_001_result.txt"

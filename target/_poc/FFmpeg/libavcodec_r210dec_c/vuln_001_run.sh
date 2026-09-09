#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating malformed AVI..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg on crafted file..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.avi -f null - > vuln_001_result.txt 2>&1 || true

# Collect any ASAN output
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. Result in vuln_001_result.txt"

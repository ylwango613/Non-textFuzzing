#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted AVI..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg against crafted input..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -c:v targa_y216 -i vuln_001_input.avi -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN log files
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. Results in vuln_001_result.txt"

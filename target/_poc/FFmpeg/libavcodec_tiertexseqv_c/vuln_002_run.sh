#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted SEQ file..."
python3 vuln_002_gen.py

echo "[*] Running ffmpeg with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  "$BIN" -y -i vuln_002_input.seq -f null - > vuln_002_result.txt 2>&1 || true

# Append any ASAN output
cat asan_002.log.* >> vuln_002_result.txt 2>/dev/null || true

echo "[*] Output:"
cat vuln_002_result.txt

echo "[*] Done."

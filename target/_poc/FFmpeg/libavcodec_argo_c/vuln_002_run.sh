#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted input file..."
python3 vuln_002_gen.py

echo "[*] Running ffmpeg with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  "$BIN" -i vuln_002_input.avi -f null - > vuln_002_result.txt 2>&1 || true

# Append any ASAN log output
cat asan_002.log.* >> vuln_002_result.txt 2>/dev/null || true

echo "[*] Result:"
cat vuln_002_result.txt

#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted HE-AAC input file..."
python3 vuln_001_gen.py

echo "[*] Running FFmpeg with aac_fixed decoder (fixed-point SBR path)..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001.log:detect_stack_use_after_return=1" \
  "$BIN" -acodec aac_fixed -i vuln_001_input.aac -f null - > vuln_001_result.txt 2>&1 || true

# Also collect any ASAN log files
cat asan_001.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. Results in vuln_001_result.txt"
cat vuln_001_result.txt

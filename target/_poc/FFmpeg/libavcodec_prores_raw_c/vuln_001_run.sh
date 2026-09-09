#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted MOV file..."
python3 vuln_001_gen.py

echo "[*] Running ASAN-instrumented ffmpeg..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.mov -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN log files to the result
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. Check vuln_001_result.txt for output."

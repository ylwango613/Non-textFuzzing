#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted input..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg on crafted MPC file..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.mpc -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN reports
for f in asan.log.*; do
    [ -f "$f" ] && cat "$f" >> vuln_001_result.txt 2>/dev/null || true
done

echo "[*] Done. Results in vuln_001_result.txt"

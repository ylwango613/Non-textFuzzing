#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating PoC input..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg with ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:detect_leaks=0" \
  "$BIN" -i vuln_001_input.avi -f null - > vuln_001_result.txt 2>&1 || true

# Collect any ASAN log shards
for f in asan.log.*; do
    [ -f "$f" ] && cat "$f" >> vuln_001_result.txt 2>/dev/null || true
done

echo "[*] Done. Result in vuln_001_result.txt"

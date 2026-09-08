#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted FIC input..."
python3 vuln_002_gen.py

echo "[*] Running ffmpeg with ASAN on crafted input..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log:detect_leaks=0" \
  "$BIN" -i vuln_002_input.fic -f null - > vuln_002_result.txt 2>&1 || true

# Merge any ASAN log files into the result
for f in asan_002.log.*; do
    [ -e "$f" ] && cat "$f" >> vuln_002_result.txt 2>/dev/null || true
done

echo "[*] Done. See vuln_002_result.txt"

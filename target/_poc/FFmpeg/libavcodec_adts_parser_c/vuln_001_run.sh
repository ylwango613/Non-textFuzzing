#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

# Generate crafted input files
python3 vuln_001_gen.py

echo "=== Running ffmpeg with ASAN ==="
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:detect_leaks=0" \
  "$BIN" -allowed_extensions ALL -i vuln_001_input.m3u8 -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN logs
for f in asan.log.*; do
    [ -f "$f" ] && cat "$f" >> vuln_001_result.txt 2>/dev/null && echo "" >> vuln_001_result.txt
done

echo "=== Done. Result in vuln_001_result.txt ==="

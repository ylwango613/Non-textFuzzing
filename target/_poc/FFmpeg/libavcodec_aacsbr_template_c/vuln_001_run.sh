#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "=== Generating malformed AAC/ADTS input file ==="
python3 vuln_001_gen.py

echo ""
echo "=== Running through FFmpeg (ASAN-instrumented binary) ==="
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001.log:detect_leaks=0" \
  "$BIN" -i vuln_001_input.aac -f null - > vuln_001_ffmpeg_out.txt 2>&1 || true

echo ""
echo "=== FFmpeg output ==="
cat vuln_001_ffmpeg_out.txt

echo ""
echo "=== Checking for ASAN reports ==="
for f in asan_001.log.*; do
    if [ -f "$f" ]; then
        echo "--- $f ---"
        cat "$f"
    fi
done

echo ""
echo "=== Done ==="

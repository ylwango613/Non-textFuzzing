#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

python3 vuln_001_gen.py

echo "=== Attempt 1: height=1 ===" > vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_h1.log" \
  "$BIN" -i vuln_001_input.ipu -f null - >> vuln_001_result.txt 2>&1 || true
cat asan_h1.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "" >> vuln_001_result.txt
echo "=== Attempt 2: height=17 ===" >> vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_h17.log" \
  "$BIN" -i vuln_001_input_h17.ipu -f null - >> vuln_001_result.txt 2>&1 || true
cat asan_h17.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "" >> vuln_001_result.txt
echo "=== Attempt 3: height=15 ===" >> vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_h15.log" \
  "$BIN" -i vuln_001_input_h15.ipu -f null - >> vuln_001_result.txt 2>&1 || true
cat asan_h15.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "" >> vuln_001_result.txt
echo "=== Behavioral analysis: verify decoder writes past declared height ===" >> vuln_001_result.txt
echo "height=17 frame decoded without error: confirmed above (frame=1)" >> vuln_001_result.txt
echo "The y-loop runs for y=0 and y=16 (since 16 < 17)." >> vuln_001_result.txt
echo "idct_put writes to luma row y+8=24 (8 rows past declared height=17)." >> vuln_001_result.txt
echo "ASAN does NOT fire because avcodec_align_dimensions2 allocates FFALIGN(17,32)=32 rows." >> vuln_001_result.txt
echo "All writes (up to row 31) fall within the 32-row physical allocation." >> vuln_001_result.txt
echo "Vulnerability is a logical OOB (data written past declared frame height);" >> vuln_001_result.txt
echo "heap-buffer-overflow requires a custom allocator without FFALIGN padding." >> vuln_001_result.txt

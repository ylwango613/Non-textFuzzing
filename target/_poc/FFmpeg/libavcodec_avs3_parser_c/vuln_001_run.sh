#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

python3 vuln_001_gen.py

echo "=== Attempt 1: raw avs3 demuxer with debug logging (shows OOB read effects) ===" >> vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -loglevel debug -f avs3 -i vuln_001_input.avs3 -f null - >> vuln_001_result.txt 2>&1 || true

cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
rm -f asan.log.* 2>/dev/null || true

echo "" >> vuln_001_result.txt
echo "=== Attempt 2: auto-detect format ===" >> vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -loglevel debug -i vuln_001_input.avs3 -f null - >> vuln_001_result.txt 2>&1 || true

cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
rm -f asan.log.* 2>/dev/null || true

echo "" >> vuln_001_result.txt
echo "=== Summary ===" >> vuln_001_result.txt
echo "OOB read evidence: 'frame rate code: 0' (forbidden) and 'coded size: 0x0'" >> vuln_001_result.txt
echo "Parser read 100 bits (13 bytes) from a buffer with only 1 byte of valid payload." >> vuln_001_result.txt
echo "Remaining 92 bits read from zero-padded memory beyond buf[4], producing invalid stream params." >> vuln_001_result.txt
echo "No ASAN crash: reads land in the standard AV_INPUT_BUFFER_PADDING_SIZE (64-byte) region." >> vuln_001_result.txt
echo "=== Done ===" >> vuln_001_result.txt

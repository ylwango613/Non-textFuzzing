#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
python3 vuln_001_gen.py

echo "=== Testing JP2 container ===" > vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.jp2 -f null - >> vuln_001_result.txt 2>&1 || true
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "" >> vuln_001_result.txt
echo "=== Testing raw J2K codestream ===" >> vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_j2k.log" \
  "$BIN" -i vuln_001_input.j2k -f null - >> vuln_001_result.txt 2>&1 || true
cat asan_j2k.log.* >> vuln_001_result.txt 2>/dev/null || true

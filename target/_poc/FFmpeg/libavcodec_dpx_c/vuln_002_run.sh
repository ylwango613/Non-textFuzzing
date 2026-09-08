#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
python3 vuln_002_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  "$BIN" -i vuln_002_input.dpx -f null - > vuln_002_result.txt 2>&1 || true
cat asan_002.log.* >> vuln_002_result.txt 2>/dev/null || true

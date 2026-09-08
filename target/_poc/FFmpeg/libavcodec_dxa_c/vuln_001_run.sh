#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "=== Generating PoC input ==="
python3 vuln_001_gen.py

echo ""
echo "=== Running FFmpeg with ASAN ==="
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -f dxa -i vuln_001_input.dxa -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN log output
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "=== Done. Result in vuln_001_result.txt ==="

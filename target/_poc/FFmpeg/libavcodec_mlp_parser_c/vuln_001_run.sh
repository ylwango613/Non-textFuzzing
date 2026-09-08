#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

python3 vuln_001_gen.py

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.thd -f null - > vuln_001_result.txt 2>&1 || true
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
echo "EXIT=$?" >> vuln_001_result.txt

echo "Run complete. Key indicators in vuln_001_result.txt:"
grep -E "Parity check|substreams|checksum|ERROR|heap" vuln_001_result.txt | head -20 || true

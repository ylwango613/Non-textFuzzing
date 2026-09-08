#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted AVI..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg under ASAN..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:halt_on_error=0" \
  "$BIN" -i vuln_001_input.avi -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN output
if ls asan.log.* 2>/dev/null; then
    echo "[*] ASAN output found, appending..."
    cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true
fi

echo "[*] Done. Result:"
cat vuln_001_result.txt

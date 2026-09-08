#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating vuln_001_input.avi ..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg with ASAN ..."
# -vcodec argo forces the Argo decoder (no standard AVI fourcc mapping exists for it)
# The AVI BITMAPINFOHEADER still provides width=8, height=10, biBitCount=8 to the decoder
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001.log" \
  "$BIN" -vcodec argo -i vuln_001_input.avi -f null - > vuln_001_result.txt 2>&1 || true

# Append any ASAN log files
for f in asan_001.log.*; do
    [ -f "$f" ] && cat "$f" >> vuln_001_result.txt && echo "" >> vuln_001_result.txt
done

echo "[*] Done. Result in vuln_001_result.txt"

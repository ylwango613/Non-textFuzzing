#!/bin/bash
set -uo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted VP6 FLV file..."
python3 vuln_001_gen.py

echo "[*] Running ffmpeg on crafted VP6 FLV file..."
# ASAN log goes to asan.log.<pid>; ffmpeg stdout/stderr go to caller's stdout
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -i vuln_001_input.flv -f null - 2>&1 || true

# Append any ASAN reports that landed in asan.log.*
for f in asan.log.*; do
    [ -f "$f" ] && { echo "--- ASAN report: $f ---"; cat "$f"; }
done 2>/dev/null || true

echo "[*] Done."

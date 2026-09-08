#!/bin/bash
# Run script for VULN 001: parse_ext_ele() Integer Overflow -> Heap Buffer Overflow
# File: /data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/aac/aacdec_usac.c lines 1993-2013
set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted USAC/MP4 input..." >&2
python3 vuln_001_gen.py >&2

echo "[*] Running ffmpeg against the crafted file..." >&2

RESULT_FILE="$(pwd)/vuln_001_result.txt"
ASAN_LOG_PREFIX="$(pwd)/asan"

ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}.log" \
  "$BIN" -i vuln_001_input.mp4 -f null - > "$RESULT_FILE" 2>&1 || true

# Append any ASAN output files
for f in "${ASAN_LOG_PREFIX}".log.*; do
    [ -f "$f" ] && { echo "=== ASAN: $f ===" >> "$RESULT_FILE"; cat "$f" >> "$RESULT_FILE"; }
done

echo "[*] ffmpeg output:" >&2
cat "$RESULT_FILE" >&2
echo "[*] Done." >&2

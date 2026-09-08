#!/bin/bash
# VULN-001 PoC: AMV Encoder Integer Overflow in Frame Flip Pointer Arithmetic
# libavcodec/mjpegenc.c, amv_encode_picture(), lines 636-638
#
# Root cause:
#   pic->data[i] += pic->linesize[i] * (vsample * s->c.height / V_MAX - 1);
#   Both operands are int. For luma (i=0): vsample=2, V_MAX=2
#   → factor = height - 1
#   → linesize[0] * (height - 1) overflows int32 when product > INT_MAX
#
# CONSTRAINT ANALYSIS:
#   av_image_check_size2() (libavutil/imgutils.c:301) enforces:
#     stride * (h + 128) < INT_MAX
#   where stride = 8*w + 1024 (conservative fallback for unknown pixel format)
#   This gives valid range: w*h < ~268M pixels (approx. 16383 x 16383)
#
#   Overflow condition requires: linesize[0] * (height-1) > INT_MAX
#   With linesize ≈ width: w * (h-1) > 2,147,483,647
#   → Minimum valid w*h for overflow: >2.1 Billion pixels
#
#   The size check (268M limit) is ~8x smaller than the overflow threshold (2.1B).
#   Therefore the overflow is NOT triggerable via external inputs.
#
# This script demonstrates the unreachability by:
#   1. Attempting overflow-triggering resolutions (rejected by size check)
#   2. Attempting the maximum valid AMV resolution (~8192x8192) to confirm no overflow

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "=== VULN-001: AMV Encoder Integer Overflow PoC ==="
echo "Binary: $BIN"
echo ""

# Step 1: Generate the reference MKV (small resolution)
echo "[*] Generating reference MKV (320x240)..."
python3 vuln_001_gen.py
echo ""

# --- Attempt 1: Overflow-triggering resolution (will be rejected by size check) ---
echo "[*] Attempt 1: 46352x46352 (overflow threshold: linesize*height = 2,148,504,304 > INT_MAX)"
echo "    Expected: REJECTED - 'Picture size ... is invalid' from av_image_check_size2()"
echo ""

ASAN_OPTIONS="abort_on_error=0:log_path=./asan1.log" \
  "$BIN" \
    -f lavfi -i "color=size=46352x46352:rate=1" \
    -vframes 1 -pix_fmt yuvj420p -c:v amv \
    vuln_001_output1.amv 2>&1 || true

echo ""

# --- Attempt 2: Second overflow resolution (will also be rejected) ---
echo "[*] Attempt 2: 65488x32800 (linesize[0]*height=65488*32800=2,147,973,200)"
echo "    Expected: REJECTED by size check"
echo ""

ASAN_OPTIONS="abort_on_error=0:log_path=./asan2.log" \
  "$BIN" \
    -f lavfi -i "color=size=65488x32800:rate=1" \
    -vframes 1 -pix_fmt yuvj420p -c:v amv \
    vuln_001_output2.amv 2>&1 || true

echo ""

# --- Attempt 3: Maximum AMV resolution that passes size check ---
# av_image_check_size2 with AV_PIX_FMT_NONE: (8*w + 1024) * (h + 128) < INT_MAX
# At 8192x8192: (65536 + 1024) * (8192 + 128) = 66560 * 8320 = 553,779,200 < INT_MAX (passes)
# linesize[0] * (height-1) = 8192 * 8191 = 67,100,672 << INT_MAX (NO overflow)
# AMV muxer requires both video + audio streams; add a null audio source
echo "[*] Attempt 3: 8192x8192 with audio (maximum valid AMV-compatible resolution)"
echo "    linesize[0]*(height-1) = 8192*8191 = 67,100,672 << INT_MAX"
echo "    Expected: ENCODES SUCCESSFULLY with no overflow (confirms unreachability)"
echo ""

# Use rate=30 and 8000 Hz audio → block_size = 8000/30 ≈ 267 (within [32-8192])
ASAN_OPTIONS="abort_on_error=0:log_path=./asan3.log" \
  "$BIN" -y \
    -f lavfi -i "color=size=8192x8192:rate=30" \
    -f lavfi -i "anullsrc=r=8000:cl=mono" \
    -vframes 1 -pix_fmt yuvj420p -c:v amv -c:a adpcm_ima_amv \
    -block_size 735 \
    -shortest \
    vuln_001_output3.amv 2>&1 || true

if ls ./asan3.log.* 1>/dev/null 2>&1; then
    echo ""
    echo "=== ASAN LOG (attempt 3) ==="
    cat ./asan3.log.* 2>/dev/null || true
fi

echo ""

# Collect any remaining ASAN logs
for logf in ./asan1.log.* ./asan2.log.*; do
    [ -f "$logf" ] && { echo "=== $logf ==="; cat "$logf"; } || true
done

echo ""
echo "=== PoC run complete ==="
echo ""
echo "CONCLUSION:"
echo "  The integer overflow in amv_encode_picture() (mjpegenc.c:637) requires"
echo "  linesize[0] * (height-1) > INT_MAX, i.e., w*h > ~2.1B pixels."
echo "  FFmpeg's av_image_check_size2() (imgutils.c:301) rejects any frame with"
echo "  stride*(h+128) >= INT_MAX, limiting frames to ~268M pixels."
echo "  The overflow threshold (2.1B) exceeds the size-check limit (268M) by 8x,"
echo "  making the vulnerability UNREACHABLE via external inputs."

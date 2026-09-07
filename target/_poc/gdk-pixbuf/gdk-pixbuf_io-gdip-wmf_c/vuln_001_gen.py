#!/usr/bin/env python3
"""
PoC Generator for VULN_001:
  Heap Out-of-Bounds Read in gdip_bitmap_get_frame_delay via Wrong item_count Formula
  Source: gdk-pixbuf/gdk-pixbuf/io-gdip-utils.c, lines 490-505

STATUS: SKIPPED
  This vulnerability is in the Windows GDI+ loader (io-gdip-wmf.c / io-gdip-utils.c).
  GDI+ is a Windows-only API. The target Linux build does not include the GDI+ loader:
    - loaders.cache is empty (dynamic loading not supported in this build)
    - No WMF/gdip .so modules found under build_test/lib/
    - strings on binary/library show no wmf/gdip symbols

VULNERABILITY DESCRIPTION:
  In gdip_bitmap_get_frame_delay() at io-gdip-utils.c:496:
    item_count = item_size / sizeof(long);

  This incorrectly divides the TOTAL allocation size (item_size, which includes
  the PropertyItem struct header: 4 bytes id + 4 bytes length + 2 bytes type + 2 bytes pad = 12 bytes)
  rather than item->length (the actual data payload length).

  The correct formula should be:
    item_count = item->length / sizeof(long);

  This inflated item_count allows an OOB read on line 498:
    *delay = ((long *)item->value)[(frame < item_count) ? frame : item_count - 1];

WHAT A WORKING PoC WOULD REQUIRE:
  On Windows with GDI+ available, an animated GIF with a crafted PropertyTagFrameDelay
  property item would be needed. The key craft:
    - A multi-frame animated GIF recognized by GDI+
    - A PropertyTagFrameDelay EXIF/property item where:
        item->length (payload bytes) is small (e.g. 4 bytes = 1 long)
        but item_size (struct + payload) is larger (e.g. 16 bytes)
      This causes item_count = 16/8 = 2 (on 64-bit) or 16/4 = 4 (on 32-bit)
      when it should be item_count = 4/4 = 1
    - Request frame index 1+ to fall into the OOB slot

GIF STRUCTURE NOTES (for reference):
  A minimal animated GIF89a with two frames:
    - Header:   GIF89a
    - LSD:      width, height, packed flags, bg color, pixel aspect
    - GCE:      Graphic Control Extension (0x21 0xF9 ...) per frame
    - Image:    Image Descriptor (0x2C ...) + pixel data per frame
    - Trailer:  0x3B
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.gif")

def build_minimal_animated_gif():
    """
    Build a minimal two-frame animated GIF89a.
    This is structurally valid but cannot trigger the OOB on Linux
    because the GDI+ loader is not available in the Linux build.
    The PropertyTagFrameDelay injection would require GDI+ APIs to exploit.
    """
    # GIF89a header
    header = b"GIF89a"

    # Logical Screen Descriptor: 10x10 pixels, 1-bit color table (2 colors), no sort, 0 bg, 0 aspect
    lsd = struct.pack("<HHBBB", 10, 10, 0b10000000, 0, 0)

    # Global Color Table: 2 colors (black, white)
    gct = b"\x00\x00\x00\xFF\xFF\xFF"

    # Netscape Application Extension (loop = 0 = infinite)
    netscape_ext = (
        b"\x21\xFF\x0B"
        b"NETSCAPE2.0"
        b"\x03\x01"
        + struct.pack("<H", 0)  # loop count = 0 (infinite)
        + b"\x00"
    )

    def make_frame(delay_cs):
        """Build one GIF frame with given delay in centiseconds."""
        # Graphic Control Extension
        gce = (
            b"\x21\xF9\x04"
            + struct.pack("<BHB", 0x00, delay_cs, 0)  # packed, delay, transparent color
            + b"\x00"
        )
        # Image Descriptor: 10x10 at offset (0,0), no local color table
        img_desc = struct.pack("<BHHHHB", 0x2C, 0, 0, 10, 10, 0)
        # Minimal LZW-compressed pixel data (min code size 2, then clear+EOI)
        lzw_min = 2
        pixel_data = b"\x02\x4C\x01\x00"  # compressed data for a 10x10 solid image
        # Sub-block structure: length byte + data + block terminator
        img_data = bytes([lzw_min]) + bytes([len(pixel_data)]) + pixel_data + b"\x00"
        return gce + img_desc + img_data

    frame1 = make_frame(10)   # 10 centiseconds
    frame2 = make_frame(20)   # 20 centiseconds

    trailer = b"\x3B"

    gif_bytes = header + lsd + gct + netscape_ext + frame1 + frame2 + trailer
    return gif_bytes


def main():
    gif_data = build_minimal_animated_gif()
    with open(OUTPUT_FILE, "wb") as f:
        f.write(gif_data)
    print(f"[SKIPPED] Generated minimal animated GIF: {OUTPUT_FILE} ({len(gif_data)} bytes)")
    print("[SKIPPED] The GDI+ loader is NOT available in the Linux build.")
    print("[SKIPPED] This vulnerability cannot be triggered on Linux.")
    print(f"[INFO]    Output written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

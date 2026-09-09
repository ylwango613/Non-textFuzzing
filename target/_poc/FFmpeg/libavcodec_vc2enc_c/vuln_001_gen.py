#!/usr/bin/env python3
import struct

# 128x128 YUV420p frame - large enough for vc2 encoder slice requirements
width, height = 128, 128
y_plane = bytes([128] * (width * height))
u_plane = bytes([128] * ((width // 2) * (height // 2)))
v_plane = bytes([128] * ((width // 2) * (height // 2)))
frame = y_plane + u_plane + v_plane

with open("vuln_001_input.yuv", "wb") as f:
    f.write(frame)

print("Generated vuln_001_input.yuv (128x128 YUV420p)")

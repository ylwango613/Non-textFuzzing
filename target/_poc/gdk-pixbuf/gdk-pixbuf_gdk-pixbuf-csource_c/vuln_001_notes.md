# VULN 001 - Heap Buffer Overflow via Zero-Length Constant Run in GdkPixdata RLE Decoder

## Status
VERIFIED_CRASH — confirmed by AddressSanitizer.

## Vulnerability Summary
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **Function**: `gdk_pixbuf_from_pixdata()` in `gdk-pixdata.c` lines 462-483
- **Root Cause**: When a GdkPixdata RLE constant run byte is `0x80`, the decoded length is `0x80 - 128 = 0`. The overflow check (`image_buffer + 0 * bpp > image_limit`) evaluates to FALSE, so decoding proceeds. The do-while loop body runs at least once (writing `bpp=4` bytes into the output buffer), then `--length` underflows an unsigned integer from `0` to `UINT_MAX`, causing ~4 billion additional write iterations past the end of the heap allocation.

## Approach

### File Generation (vuln_001_gen.py)
A 29-byte crafted GdkPixdata file is generated using Python's `struct` module (no C code, no compilation):

- **Header (24 bytes, big-endian)**:
  - `magic = 0x47646b50` ("GdkP")
  - `length = 29` (total file size)
  - `pixdata_type = 0x02010002` (RGBA + 8-bit samples + RLE encoding)
  - `rowstride = 4` (1 pixel × 4 bytes/pixel)
  - `width = 1`, `height = 1`
- **Pixel data (5 bytes)**:
  - `0x80` — constant RLE run byte; decoded length = 0 (triggers bug)
  - `0xFF 0x00 0x00 0xFF` — RGBA red pixel value

### Length Check Bypass
The stream-level length check is: `stream_length(29) < pixdata->length(29) - 24 = 5` → `29 < 5` → FALSE → check passes without truncation. The bug is reached inside `gdk_pixbuf_from_pixdata`.

### Crash Mechanism
1. Output buffer allocated: `width * height * bpp = 1 * 1 * 4 = 4 bytes`
2. RLE decoder enters do-while with `length = 0`
3. First iteration: writes 4 bytes at `image_buffer[0..3]` — valid
4. `--length` underflows: `0 - 1 = UINT_MAX` (4294967295)
5. Loop continues; second write at `image_buffer[4]` — 0 bytes past end of allocation → ASAN detects heap-buffer-overflow

## Observed ASAN Output
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000d14
WRITE of size 4 at 0x502000000d14 thread T0
  #0 gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xad028)
  #1 try_load (libgdk_pixbuf-2.0.so.0+0xc74fb)
  ...
0x502000000d14 is located 0 bytes to the right of 4-byte region [0x502000000d10,0x502000000d14)
```

The shadow byte `[04]` (partially addressable) confirms 4 bytes were allocated and the write landed immediately past the end.

## Files
| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.gdkp` (29-byte malicious GdkPixdata file) |
| `vuln_001_run.sh` | Runs the generator then invokes the ASAN-instrumented binary |
| `vuln_001.gdkp` | The crafted input file |
| `asan.log.*` | Raw ASAN output capturing the crash details |
| `vuln_001_result.txt` | Combined stdout/stderr and ASAN log summary |
| `vuln_001_status.txt` | Machine-readable crash status |
| `vuln_001_notes.md` | This document |

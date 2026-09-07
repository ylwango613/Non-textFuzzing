# VULN 002 - pal2rgb heap-buffer-overflow via unchecked _TIFFmalloc result

## Status: VERIFIED_CRASH

## ASAN Report
```
TIFFFillStrip: vuln_002.tif: Read error on strip 0; got 1 bytes, expected 536870911.
==425823==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000071
SUMMARY: AddressSanitizer: heap-buffer-overflow (...pal2rgb+0x8305) in main
```

## Root Cause (as triggered)

The vulnerability is at `pal2rgb.c` line 180:
```c
ibuf = (unsigned char*)_TIFFmalloc(TIFFScanlineSize(in));
```

### Width selection rationale

The originally described width `0xFFFFFFFF` triggers libtiff's internal integer overflow
protection in `multiply()` inside `TIFFScanlineSize`, causing `TIFFReadDirectory` to reject
the file with "cannot handle zero scanline size" before pal2rgb reaches line 180.

The PoC instead uses `imagewidth = 0x1FFFFFFF` (536870911):
- For 8bpp: `multiply(0x1FFFFFFF, 8) = 0xFFFFFFF8` fits in uint32 - no overflow detected
- `TIFFScanlineSize` returns 536870911 bytes (~512 MB)
- `_TIFFmalloc(536870911)` succeeds but allocates only a small backing buffer (ASAN heap)

### Crash mechanism

1. `ibuf = _TIFFmalloc(536870911)` - allocates a heap buffer; ASAN maps a small region
2. `TIFFReadScanline(in, ibuf, 0, 0)` is called; libtiff reads only 1 byte (StripByteCounts=1)
3. The pixel loop at line 188 iterates `x` from 0 to 536870910 accessing `ibuf[x]`
4. ASAN detects the heap-buffer-overflow at `ibuf[1]` (only 1 byte was written)

This confirms the missing NULL-check pattern: even when malloc returns non-NULL, the
absence of size validation leads to out-of-bounds access. If malloc returned NULL
(possible on systems without overcommit or under memory pressure), the crash would be
a NULL pointer dereference instead (SIGSEGV on address 0x0).

## CWE
- CWE-476: NULL Pointer Dereference (original description)
- CWE-122: Heap-based Buffer Overflow (observed crash)
- Both stem from the same missing validation of `_TIFFmalloc` return vs actual data size

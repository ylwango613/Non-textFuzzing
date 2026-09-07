# VULN 001 - pal2rgb Heap Buffer Overflow (CWE-122)

## Status: VERIFIED_CRASH

## PoC Approach

`vuln_001_gen.py` builds a crafted TIFF file with:
- `ImageWidth = 178,956,971` (PHOTOMETRIC_PALETTE, BitsPerSample=8, SamplesPerPixel=1)
- PackBits compression (tag 32773) applied to a single all-zero scanline of 178,956,971 bytes
- The PackBits strip encodes 1,398,101 runs of 128 zero bytes and one trailing run of 43 bytes,
  producing ~2.8 MB of compressed data (instead of ~170 MB uncompressed)
- A zeroed Colormap (768 SHORTs)

The TIFF is structurally valid and libtiff parses and decompresses it successfully.

## Crash Trigger Chain

1. pal2rgb opens the input TIFF and creates an output RGB TIFF (samplesperpixel=3).
2. `TIFFScanlineSize(out)` computes `imagewidth * samples * bits / 8`:
   - `178,956,971 * 3 = 536,870,913` pixels
   - `536,870,913 * 8 = 4,294,967,304` bits -> overflows `uint32` to **8**
3. The overflow is detected; `multiply()` returns 0; `TIFFScanlineSize()` returns 0.
4. pal2rgb prints "Integer overflow in TIFFScanlineSize" warnings but continues.
5. `obuf = _TIFFmalloc(0)` -> on Linux/glibc ASAN allocates a **1-byte** region
   (ASAN maps malloc(0) to a minimal-sized allocation for detectability).
6. The pixel copy loop iterates over `imagewidth = 178,956,971` pixels, writing
   3 output bytes per pixel into `obuf` -> writes 536,870,913 bytes past a 1-byte buffer.
7. ASAN catches the **first out-of-bounds WRITE** immediately at byte 2.

## ASAN Report Summary

```
AddressSanitizer: heap-buffer-overflow on address 0x502000000071
WRITE of size 1 at 0x502000000071 thread T0
  #0 main  pal2rgb+0x8305
0x502000000071 is located 0 bytes to the right of 1-byte region
  [0x502000000070, 0x502000000071)
allocated by:
  #0 __interceptor_malloc
  #1 _TIFFmalloc  libtiff.so.3
  #2 main  pal2rgb
```

## Memory Note

`ibuf = _TIFFmalloc(imagewidth)` requires ~171 MB. On this system the allocation
succeeded, so VULN 001 (obuf overflow) was triggered directly rather than VULN 002
(ibuf NULL dereference).

## Files

| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Python script building the crafted TIFF |
| `vuln_001.tif`   | Generated PoC input (2,797,874 bytes) |
| `vuln_001_run.sh` | Shell script invoking pal2rgb under ASAN |
| `vuln_001_result.txt` | Full pal2rgb + ASAN output |
| `asan.log.*`     | Raw ASAN log file |

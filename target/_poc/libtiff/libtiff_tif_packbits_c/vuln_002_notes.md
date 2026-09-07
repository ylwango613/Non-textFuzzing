# VULN 002 - PackBitsDecode run-length branch missing input guard

## Vulnerability Summary
- File: `libtiff/libtiff/tif_packbits.c`, line 249
- Function: `PackBitsDecode()`
- CWE: CWE-125 (Out-of-bounds Read)

## Root Cause
`bp` is declared `char*`. When a header byte of 0xFF is read:
- On signed-char platforms: `n = (long)(char)0xFF = -1` directly
- On unsigned-char platforms: `n = (long)255`, then `if (n >= 128) n -= 256` → `n = -1`

Either way `n = -1`, which passes the `n < 0` check and the `n == -128` NOP check.
After reading 1 input byte, `cc` drops to 0. The code then executes:

```c
b = *bp++, cc--;   /* line 249 — no cc > 0 guard here */
```

This reads 1 byte past the end of `tif_rawdata` (heap OOB read by 1 byte).

## Trigger Condition
A PACKBITS-compressed strip whose raw data is exactly 1 byte = `0xFF`:
- `StripByteCounts = 1` → `tif_rawcc = 1`
- Strip data = `[0xFF]` (run-length header, no following data byte)

## PoC Approach
`vuln_002_gen.py` constructs a minimal valid TIFF (123 bytes):
- Little-endian header, 9-tag IFD (4×1 px, 8-bit, PackBits)
- Strip at offset 122: single byte `0xFF`
- `StripByteCounts = 1`

## Why tiffsplit Cannot Trigger the Vulnerability
`tiffsplit` uses `TIFFReadRawStrip()` (see `tools/tiffsplit.c:251`) which calls
`TIFFReadRawStrip1()` directly. This path reads the compressed bytes verbatim from
disk into a buffer without invoking any codec. `PackBitsDecode` is never called.

Tools that do trigger `PackBitsDecode` include `tiff2bw`, `tiff2rgba`, `tiffcp`
(without `-c none`), and `tiffinfo -D` — all of which call `TIFFReadEncodedStrip`
or `TIFFReadScanline`, which route through the decompressor.

## Expected Behavior (if triggered via a decoding tool)
ASAN would report:
```
ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at 0x... thread T0
    #0 PackBitsDecode tif_packbits.c:249
```

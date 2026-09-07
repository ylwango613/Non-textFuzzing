# VULN 002 — gtStripContig heap OOB read: PoC Notes

## Vulnerability Summary

**CWE-125** — Out-of-bounds Read in `gtStripContig()` (`tif_getimage.c`).

### Root Cause

When a strip-organised TIFF has parameters that cause integer overflow in
`TIFFStripSize()` (specifically `rowsperstrip × imagewidth × spp × bps/8 >
UINT32_MAX`), the function returns 0. `_TIFFmalloc(0)` may return a non-NULL
pointer on some implementations, bypassing the `if (buf == 0)` guard.
Afterwards the `put` callback (`gtStripContig`) reads `imagewidth × spp` bytes
per row from the zero-sized buffer — a heap out-of-bounds read.

### Overflow trigger

```
rowsperstrip(65536) × imagewidth(65536) × spp(4) × 1 = 2^34 → 0 in uint32
```

## Why tiffsplit is SKIPPED for this vulnerability

`tiffsplit` copies TIFF files strip-by-strip using raw I/O:

```
main() → TIFFOpen() → tiffcp() → cpStrips()
```

`cpStrips()` calls `TIFFStripSize()` then `TIFFReadRawStrip()`. It does **not**
call:
- `TIFFRGBAImageBegin()`
- `TIFFRGBAImageGet()`
- `gtStripContig()`

Therefore the vulnerable code path in `tif_getimage.c` is **unreachable** from
`tiffsplit`. The crafted TIFF will be processed without triggering the OOB read
(tiffsplit exits normally or with a non-ASAN I/O error).

## TIFF file construction

`vuln_002_gen.py` constructs a minimal little-endian strip TIFF with:

| Tag               | Value  | Effect                                     |
|-------------------|--------|--------------------------------------------|
| ImageWidth        | 65536  | Large width participates in overflow       |
| ImageLength       | 4      | Small: ensures put loop actually runs      |
| SamplesPerPixel   | 4      | Multiplier in overflow formula             |
| BitsPerSample     | 8      | ×1 byte per sample                         |
| RowsPerStrip      | 65536  | **Key**: 65536×65536×4 > UINT32_MAX → 0   |
| Compression       | 1      | Uncompressed, no decompressor interference |
| PlanarConfig      | 1      | CONTIG, required for gtStripContig path    |
| StripOffsets      | 142    | Points to 16 bytes of real data            |
| StripByteCounts   | 16     | Consistent with actual strip data          |

## Tools that CAN trigger VULN 002

Tools that call the `TIFFRGBAImage` API:
- `tiff2rgba`
- `tiffgt`
- Custom harnesses calling `TIFFRGBAImageBegin()` / `TIFFRGBAImageGet()`

Running `tiff2rgba vuln_002.tif /dev/null` (if built with ASan) is expected
to produce an `AddressSanitizer: heap-buffer-overflow` error in `gtStripContig`.

## Status

**SKIPPED** — the vulnerable function (`gtStripContig`) is not reachable via
the `tiffsplit` code path.

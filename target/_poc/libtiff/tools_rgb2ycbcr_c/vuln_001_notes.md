# VULN 001 Notes: Integer overflow in cvtRaster() output-buffer size

## Vulnerability Summary

**Tool**: rgb2ycbcr (tools/rgb2ycbcr.c, lines 250-264)

**Root cause**: In `cvtRaster()`, the output-buffer size `cc` is computed via uint32 arithmetic:

```c
uint32 rwidth  = roundup(width, horizSubSampling);   // horizSubSampling=2
uint32 rheight = roundup(height, vertSubSampling);   // vertSubSampling=2
uint32 nrows   = (rowsperstrip > rheight ? rheight : rowsperstrip);
uint32 rnrows  = roundup(nrows, vertSubSampling);

cc = rnrows*rwidth + 2*((rnrows*rwidth) / (horizSubSampling*vertSubSampling));
buf = (unsigned char*)_TIFFmalloc(cc);   // allocates only `cc` bytes
```

With `width=0x80000001, height=1`:
- `rwidth  = 0x80000002`
- `rnrows  = 2`
- `rnrows*rwidth = 0x100000004` overflows uint32 to `4`
- `cc = 4 + 2*(4/4) = 6`  => only 6 bytes allocated
- `cvtStrip()` would then write approximately 2×0x80000002 bytes → heap OOB write

## PoC Approach

Created a minimal TIFF with:
- TIFFTAG_IMAGEWIDTH = 0x80000001
- TIFFTAG_IMAGELENGTH = 1
- No compression, RGB photometric, 8 bps, 3 samples/pixel

## Why the crash is NOT reached in practice

Two blocking conditions prevent reaching the vulnerable code path:

### Barrier 1: libtiff internal sanity check
`TIFFReadDirectory()` calls `TIFFScanlineSize()` which itself overflows when computing
`width * bitspersample * sampleperpixel / 8` for width=0x80000001. libtiff prints:

    vuln_001.tif: Integer overflow in TIFFScanlineSize.
    TIFFReadDirectory: cannot handle zero scanline size.

The file is rejected immediately. The application never reaches `tiffcvt()`.

### Barrier 2: Raster memory exhaustion (secondary)
Even if the TIFF passed the scanline check, `tiffcvt()` (line 297) would call
`_TIFFCheckMalloc(in, pixel_count=0x80000001, sizeof(uint32)=4, ...)` to allocate
~8.6 GB for the RGBA raster. This would fail (OOM / NULL) on typical systems,
causing an early return before `cvtRaster()` is ever called.

## Actual run output

    vuln_001.tif: Integer overflow in TIFFScanlineSize.
    vuln_001.tif: Integer overflow in TIFFTileRowSize.
    vuln_001.tif: Integer overflow in TIFFScanlineSize.
    TIFFReadDirectory: vuln_001.tif: cannot handle zero scanline size.

No ASAN/UBSAN errors emitted. Process exits normally with code 0.

## Status: UNVERIFIED

The integer overflow in `cc` is a real source-code vulnerability (the arithmetic in
cvtRaster lines 255-256 has no bounds check), but is not practically reachable via
the available binary because libtiff's own `TIFFScanlineSize` overflow guard rejects
the crafted image first.

A future trigger might be possible by:
1. Patching out the TIFFScanlineSize check in a custom build.
2. Using a system with sufficient RAM/overcommit to survive the raster allocation.

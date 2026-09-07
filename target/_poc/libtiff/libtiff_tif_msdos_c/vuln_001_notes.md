# VULN-001: Signed-to-unsigned conversion in _TIFFmemcpy/_TIFFmemset

## Summary

A signed-to-unsigned integer conversion vulnerability in `_TIFFmemcpy()` and `_TIFFmemset()`
allows a specially crafted TIFF file to trigger an out-of-bounds write (CWE-787).

- **CWE**: CWE-195 (Signed to Unsigned Conversion Error) -> CWE-787 (Out-of-bounds Write)
- **Source file**: `tif_msdos.c` lines 150-158; identical pattern in `tif_unix.c`
- **Affected binary**: `tiffsplit` (and any tool using libtiff)

## Vulnerable Code

### tif_unix.c (Linux equivalent of tif_msdos.c)

```c
void _TIFFmemcpy(tdata_t d, const tdata_t s, tsize_t c) {
    memcpy(d, s, (size_t) c);  // BUG: no check for c < 0 before cast
}

void _TIFFmemset(tdata_t p, int v, tsize_t c) {
    memset(p, v, (size_t) c);  // BUG: same issue
}
```

`tsize_t` is a signed type (`int32_t` on 32-bit, `int64_t` on 64-bit). When `c` is negative,
the cast to `size_t` (unsigned) produces a massive value (e.g., `-1` becomes `0xFFFFFFFFFFFFFFFF`
on 64-bit), causing `memcpy`/`memset` to write far beyond the allocated buffer.

## Trigger Path

```
tiffsplit
  -> TIFFOpen()
  -> TIFFClientOpen()
  -> TIFFReadDirectory()
    -> Reads StripByteCounts tag (0x0117) = 0
  -> TIFFReadRawStrip()
    -> TIFFRawStripSize() returns (tsize_t)-1   [because StripByteCounts[strip]==0]
  -> Decode path with LZW + Predictor=2:
    -> tif_predict.c: fpAcc()
      -> cc = TIFFRawStripSize(tif)  [= -1 as tsize_t]
      -> tmp = _TIFFmalloc(cc)       [= _TIFFmalloc(SIZE_MAX)]  <- heap exhaustion / OOM
      -> _TIFFmemcpy(tmp, cp0, cc)   [= memcpy with size SIZE_MAX] <- OOB WRITE
```

## Alternate Path (tif_getimage.c)

```
TIFFRGBAImageGet()
  -> bufsize = width * height * samplesPerPixel  [can overflow]
  -> buf = _TIFFmalloc(bufsize)
  -> _TIFFmemset(buf, 0, bufsize)                <- OOB WRITE if bufsize overflowed
```

## PoC Files

| File | Strategy | Key Field |
|------|----------|-----------|
| `vuln_001.tif` | LZW + Predictor=2, StripByteCounts=0 | Primary trigger path |
| `vuln_001_v2.tif` | LZW + Predictor=2, StripByteCounts=0xFFFFFFFF | Large count variant |
| `vuln_001_v3.tif` | No compression, StripByteCounts=0 | Alternate path |
| `vuln_001_v4.tif` | Large ImageWidth, StripByteCounts=0 | Buffer overflow path |

## TIFF Structure (vuln_001.tif)

```
Offset  Size  Field
0       4     Header: 'II' + 0x002A (little-endian)
4       4     IFD offset = 8
8       2     IFD entry count = 10
10      120   IFD entries (10 * 12 bytes):
              - ImageWidth = 64 (SHORT)
              - ImageLength = 64 (SHORT)
              - BitsPerSample = 8 (SHORT)
              - Compression = 5/LZW (SHORT)
              - PhotometricInterp = 1/BlackIsZero (SHORT)
              - StripOffsets -> data after IFD (LONG)
              - SamplesPerPixel = 1 (SHORT)
              - RowsPerStrip = 64 (SHORT)
              - StripByteCounts = 0 (LONG)  <-- VULNERABILITY TRIGGER
              - Predictor = 2/HorizDiff (SHORT)
130     4     Next IFD = 0
134     64    Fake strip data
```

## Detection

The binary is compiled with AddressSanitizer (libasan) and UBSanitizer (libubsan).
An exploitable condition would produce errors like:

- `AddressSanitizer: heap-buffer-overflow`
- `AddressSanitizer: allocator is out of memory trying to allocate SIZE_MAX bytes`
- `runtime error: signed integer overflow`

## Impact

- **Severity**: High (potential remote code execution via crafted TIFF file)
- **Attack vector**: Malicious TIFF file processed by any libtiff-using application
- **Affected versions**: libtiff versions not validating negative `tsize_t` before memcpy/memset

## Fix

Add a guard before the cast:

```c
void _TIFFmemcpy(tdata_t d, const tdata_t s, tsize_t c) {
    if (c <= 0) return;  // or assert
    memcpy(d, s, (size_t) c);
}
```

Or use `tmsize_t` (a signed size type) consistently and validate at the call sites.

# VULN 002 - Signed-to-unsigned conversion in _TIFFmalloc/_TIFFrealloc leads to NULL dereference

## Vulnerability Summary

- **ID**: VULN 002
- **CWE**: CWE-195 (Signed to Unsigned Conversion Error) → CWE-476 (NULL Pointer Dereference)
- **Affected files**: `tif_msdos.c` (same pattern in `tif_unix.c`)
- **Lines**: 131-147 in tif_msdos.c

## Root Cause

`_TIFFmalloc()` and `_TIFFrealloc()` accept `tsize_t` (a signed type) but pass it directly to `malloc()`/`realloc()` which expect `size_t` (unsigned). When a negative value such as `(tsize_t)-1` is passed, the signed-to-unsigned conversion produces `SIZE_MAX` (~18 EB), causing `malloc()` to return NULL. If the caller does not check for NULL before dereferencing, a NULL pointer dereference occurs.

```c
void* _TIFFmalloc(tsize_t s) {
    return (malloc((size_t) s));  // no negativity check on tsize_t s
}
void* _TIFFrealloc(tdata_t p, tsize_t s) {
    return (realloc(p, (size_t) s));  // same issue
}
```

## Trigger Path

```
tiffsplit
  → TIFFOpen
  → TIFFClientOpen
  → TIFFReadDirectory
  → TIFFReadRawStrip
  → TIFFRawStripSize()
      [if StripByteCount == 0 or > INT32_MAX: return (tsize_t)-1]
  → caller passes -1 to _TIFFmalloc(-1)
  → malloc(SIZE_MAX) returns NULL
  → caller dereferences NULL → SIGSEGV / ASAN crash
```

## Trigger Condition

Setting the TIFF tag `StripByteCounts` (0x0117) to:
- `0` — explicitly checked and returns `(tsize_t)-1` in `tif_strip.c`
- `0xFFFFFFFF` (UINT_MAX, > INT32_MAX) — also triggers the same return value

## PoC File Construction

The PoC constructs a minimal valid little-endian TIFF with:
- ImageWidth=64, ImageLength=64
- BitsPerSample=8, Compression=1 (no compression)
- PhotometricInterpretation=1 (BlackIsZero)
- SamplesPerPixel=1, RowsPerStrip=64
- StripOffsets pointing to 64 zero bytes of dummy data
- **StripByteCounts=0xFFFFFFFF** (the key trigger value)

## Expected Outcome

When `tiffsplit` processes this file, it calls `TIFFReadRawStrip`, which calls `TIFFRawStripSize()`. Because `StripByteCounts=0xFFFFFFFF > INT32_MAX`, `TIFFRawStripSize()` returns `(tsize_t)-1`. This value is passed to `_TIFFmalloc(-1)`, which calls `malloc(SIZE_MAX)`, returning NULL. The subsequent dereference of the NULL buffer causes a segfault or ASAN-detected NULL dereference.

## Files

- `vuln_002_gen.py` — Python script to generate the malicious TIFF
- `vuln_002_run.sh` — Shell script to run tiffsplit against it
- `vuln_002.tif` — Generated malicious TIFF file
- `vuln_002_result.txt` — Output of the tiffsplit run
- `vuln_002_status.txt` — Final status and verdict

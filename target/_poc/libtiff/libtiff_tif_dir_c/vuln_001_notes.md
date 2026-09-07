# VULN 001: Heap OOB Read in checkInkNamesString

## Summary

A heap out-of-bounds read occurs in `checkInkNamesString()` in `libtiff/tif_dir.c`
when a crafted TIFF file sets `TIFFTAG_INKNAMES` (tag 333) with fewer null-terminated
ink names than indicated by `TIFFTAG_SAMPLESPERPIXEL`.

- **CWE**: CWE-125 (Out-of-bounds Read)
- **File**: `libtiff/libtiff/tif_dir.c`, lines 119-125
- **Trigger path**: `tiffsplit` -> `TIFFOpen` -> `TIFFReadDirectory` ->
  `TIFFSetField(TIFFTAG_INKNAMES)` -> `checkInkNamesString()`

## Root Cause

The vulnerable loop in `checkInkNamesString()`:

```c
ep = s + slen;          // ep points to sentinel '\0' added by tif_dirread.c
cp = s;
for (; i > 0; i--) {   // i = samplesperpixel = 3
    for (; *cp != '\0'; cp++)   // reads *cp BEFORE checking boundary
        if (cp >= ep)
            goto bad;
    cp++;               // advance past '\0'
}
```

When the INKNAMES string "ab" (slen=2) fills positions s[0] and s[1] with no
internal '\0', libtiff appends a sentinel at s[2]. The inner loop reads s[0]='a',
s[1]='b', then reads *s[2]='\0' (the sentinel) and exits. The boundary check
(`cp >= ep` where ep=s+2) is never triggered because the read happens before the
check. Then `cp++` advances to s+3 (one past the allocated buffer). With
SamplesPerPixel=3, the next iteration reads *(s+3), which is out of bounds.

## PoC Construction

The crafted TIFF (`vuln_001.tif`) contains:

| Tag | Value | Purpose |
|-----|-------|---------|
| ImageWidth (256) | 1 | Minimal image |
| ImageLength (257) | 1 | Minimal image |
| BitsPerSample (258) | 8 | 8-bit samples |
| Compression (259) | 1 | No compression |
| PhotometricInterpretation (262) | 5 | Separated/CMYK (required for INKNAMES) |
| StripOffsets (273) | offset | Pixel data location |
| SamplesPerPixel (277) | 3 | Claims 3 ink names needed |
| RowsPerStrip (278) | 1 | One row per strip |
| StripByteCounts (279) | 3 | 3 bytes of pixel data |
| INKNAMES (333) | "ab" (2 bytes, slen=2) | Only 0 complete names |

With SamplesPerPixel=3 and INKNAMES providing 0 complete null-terminated names
in 2 bytes, the function reads 2+ bytes past the end of the allocation.

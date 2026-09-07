# VULN 001 — JPEGDecodeRaw Heap Buffer Overflow — SKIPPED

## Vulnerability

- **Function**: `JPEGDecodeRaw()` in `libtiff/libtiff/tif_jpeg.c` (lines 984–1097)
- **Trigger path**: `TIFFReadEncodedStrip()` → `TIFFFillStrip()` → `JPEGDecodeRaw()`
- **Root cause**: `bytesperline` is computed by `JPEGPreDecode()` using `TIFFOldScanlineSize()` (line 716 of tif_jpeg.c), which ignores YCbCr subsampling. For ImageWidth=1 with 4:2:0 subsampling the JPEG library produces a full MCU row (2×2 luma + 1 chroma each), but the allocated `buf` is sized for only 1 pixel × 3 samples = 3 bytes. `JPEGDecodeRaw()` then writes far more bytes into that buffer, causing a heap OOB write.

## Why tiffsplit cannot trigger this

`tiffsplit` reads strip data using `TIFFReadRawStrip()`, not `TIFFReadEncodedStrip()`.

Relevant code in `libtiff/tools/tiffsplit.c`, function `cpStrips()` (line 251):

```c
if (TIFFReadRawStrip(in, s, buf, bytecounts[s]) < 0 ||
    TIFFWriteRawStrip(out, s, buf, bytecounts[s]) < 0) {
```

`TIFFReadRawStrip()` reads the compressed bytes directly from the file into a buffer without invoking any codec. It never calls `TIFFFillStrip()` or the JPEG decode path. Therefore `JPEGPreDecode()` and `JPEGDecodeRaw()` are never reached, and the heap OOB write cannot occur.

## Conclusion

The only valid trigger binary (`tiffsplit`) does not call the vulnerable code path. The PoC is **SKIPPED** because the binary's strip-reading strategy (raw passthrough) is fundamentally incompatible with the vulnerability's required trigger path (decoded strip reading).

To actually trigger this vulnerability a different host binary would be needed — one that calls `TIFFReadEncodedStrip()` or `TIFFReadScanline()` on a JPEG-compressed TIFF, such as `tiffinfo -d`, `tiffdump`, or a custom test harness.

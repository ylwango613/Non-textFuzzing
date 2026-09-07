# VULN 001 — G3 1D Fax Decoder CLEANUP_RUNS Heap OOB Write

## Status: SKIPPED

## Reason

`tiffsplit` cannot trigger this vulnerability because it **never invokes the fax decoder**.

### Evidence from source

In `/data/ylwang/non-textfuzz/target/libtiff/tools/tiffsplit.c`:

- `cpStrips()` (line 231–261) calls **`TIFFReadRawStrip`** (line 251), which reads raw compressed bytes directly without decoding.
- `cpTiles()` (line 263–294) calls **`TIFFReadRawTile`** (line 284), same bypass.

Neither path calls `TIFFReadEncodedStrip`, `TIFFReadScanline`, or any function that would invoke `Fax3Decode1D` in `tif_fax3.c`.

### Consequence

No matter how the G3/CCITT compressed strip data is crafted, `tiffsplit` copies it verbatim from input to output without decompressing it. The `CLEANUP_RUNS` OOB write in the fax decoder is therefore unreachable via `tiffsplit`.

### Correct trigger binary

The vulnerability described (heap OOB write in `Fax3Decode1D` → `CLEANUP_RUNS`) is only reachable through tools that decode fax data, such as `fax2tiff`, `tiffinfo`, `tiff2pdf`, `tiff2ps`, or any application calling `TIFFReadEncodedStrip`/`TIFFReadScanline` on a CCITT-compressed TIFF.

# VULN 001 – PoC Notes

## Vulnerability Summary

- **Function**: `gtTileContig()` in `libtiff/tif_getimage.c`
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Root cause**: When `TileWidth=65536` and `TileLength=65536`, the product
  `65536 × 65536 × SamplesPerPixel × BytesPerSample` equals 2^32, which
  overflows a 32-bit signed/unsigned integer to 0 inside libtiff's
  `multiply()` helper. `TIFFTileSize()` therefore returns 0.
  `_TIFFmalloc(0)` on Linux returns a non-NULL unique pointer, so the
  `if (buf == 0)` guard in `gtTileContig` is bypassed. The subsequent
  `put` callback then reads actual tile pixel data (based on real image
  dimensions) into the zero-byte allocation, causing a heap out-of-bounds
  read.

## Why tiffsplit Cannot Trigger This Path

`tiffsplit` does **not** call any `TIFFRGBAImage*` API. Its processing
pipeline for tiled images is:

```
main()
  TIFFOpen()
  tiffcp()   <- copies IFD tags from input to output
    cpTiles()
      TIFFTileSize()          <- overflows to 0
      _TIFFmalloc(0)          <- returns non-NULL on Linux
      TIFFNumberOfTiles()
      for each tile:
        if bytecounts[t] > bufsize → _TIFFrealloc(buf, bytecounts[t])
        TIFFReadRawTile()     <- reads raw compressed/uncompressed bytes
        TIFFWriteRawTile()    <- writes to output file
  TIFFClose()
```

The vulnerable code path `gtTileContig` is reached only via:

```
TIFFRGBAImageBegin() -> PickContigCase() -> img->get = gtTileContig
TIFFRGBAImageGet()   -> gtTileContig()
```

Neither `TIFFRGBAImageBegin()` nor `TIFFRGBAImageGet()` is called anywhere
in `tiffsplit.c`.

Additionally, `cpTiles()` itself is not vulnerable in this scenario: even
though `TIFFTileSize` returns 0, the code checks
`if (bytecounts[t] > (uint32) bufsize)` and `_TIFFrealloc`s the buffer to
the actual byte count before calling `TIFFReadRawTile`, so no OOB occurs.

## PoC File Construction (vuln_001_gen.py)

The generated `vuln_001.tif` is a little-endian, single-page, tiled TIFF
with the following properties:

| Parameter | Value | Effect |
|---|---|---|
| ImageWidth | 256 | Small enough for put loop to execute |
| ImageLength | 256 | Small enough for put loop to execute |
| TileWidth | 65536 | Triggers 32-bit overflow in TIFFTileSize |
| TileLength | 65536 | Triggers 32-bit overflow in TIFFTileSize |
| SamplesPerPixel | 1 | Keeps multiplier at 1 |
| BitsPerSample | 8 | 1 byte per sample |
| Compression | 1 (NONE) | No decompression needed |
| PhotometricInterp | 1 (BlackIsZero) | Accepted by TIFFRGBAImageOK |
| PlanarConfig | 1 (CONTIG) | Selects CONTIG case / gtTileContig |
| TileOffsets | points to 65536-byte block | Valid on-disk tile data |
| TileByteCounts | 65536 | 256×256 actual bytes |

## Status

**SKIPPED** — `tiffsplit` does not call `TIFFRGBAImageGet()` or any
`TIFFRGBAImage*` function, so the `gtTileContig` code path is unreachable
through this tool. To exercise this vulnerability, a harness that calls
`TIFFRGBAImageBegin()` + `TIFFRGBAImageGet()` (e.g. `tiff2rgba` or a
custom fuzzing driver) would be required.

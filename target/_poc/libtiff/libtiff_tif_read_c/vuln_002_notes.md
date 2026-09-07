# VULN 002 - TIFFReadRawTile1 uint32 Overflow OOB Read

## Vulnerability Summary

**CWE-125**: Out-of-bounds Read in `TIFFReadRawTile1()` (`tif_read.c`, lines 440-451).

The mmap branch computes `offset + size` using `uint32` arithmetic to guard a
`_TIFFmemcpy`. When `offset` is `0xFFFFFF00` and `size` is `256`, the addition
wraps to `0`, making the guard `0 > tif_size` always false for any non-empty
file. Control then falls to `_TIFFmemcpy(buf, tif->tif_base + 0xFFFFFF00, 256)`,
which reads 256 bytes starting ~4 GB past the beginning of the mapped file region.

## Trigger Path

```
tiffsplit main()
  → TIFFOpen()
  → tiffcp()
  → cpTiles()
  → TIFFReadRawTile()
  → TIFFReadRawTile1()   ← overflow + OOB read here
```

## PoC Approach

`vuln_002_gen.py` builds a minimal 186-byte little-endian tiled TIFF:

| Tag | Value |
|-----|-------|
| ImageWidth / ImageLength | 16 |
| BitsPerSample | 8 |
| Compression | 1 (none) |
| TileWidth / TileLength | 16×16 (one tile covers the whole image) |
| TileOffsets[0] | `0xFFFFFF00` |
| TileByteCounts[0] | `256` |

The file is valid enough for `tiffsplit` to open it and attempt to copy tile
data, but the crafted offsets trigger the integer overflow before the copy.

## Observed Crash

```
AddressSanitizer: SEGV on unknown address 0x7f6b85975f00
  (pc ... bp ... sp ... T0)
SUMMARY: AddressSanitizer: SEGV in memcpy
```

Address `0x7f...f00` corresponds to `mmap_base + 0xFFFFFF00`, confirming the
OOB read past the end of the mapped file.

## Files

| File | Description |
|------|-------------|
| `vuln_002_gen.py` | Generates `vuln_002.tif` |
| `vuln_002_run.sh` | Runs generator then `tiffsplit` under ASAN |
| `vuln_002.tif` | Malicious 186-byte tiled TIFF |
| `vuln_002_result.txt` | Raw stdout/stderr + ASAN log excerpt |
| `vuln_002_status.txt` | `VERIFIED_CRASH` |

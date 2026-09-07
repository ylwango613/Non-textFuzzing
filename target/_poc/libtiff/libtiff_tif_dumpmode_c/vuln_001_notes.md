# VULN 001 — DumpModeSeek Integer Overflow — SKIPPED

## Why this vulnerability is skipped

### Vulnerability recap

`DumpModeSeek` (libtiff/tif_dumpmode.c:97-101) computes:

```c
tif->tif_rawcp += nrows * tif->tif_scanlinesize;
tif->tif_rawcc -= nrows * tif->tif_scanlinesize;
```

Both operands are unsigned 32-bit under C arithmetic promotion. When `nrows *
tif_scanlinesize` wraps mod 2^32 into `[0x80000000, 0xFFFFFFFF]`, the result is
interpreted as a large negative `tsize_t` (signed 32-bit), causing `tif_rawcc`
to increase instead of decrease and `tif_rawcp` to advance gigabytes past the
heap buffer. A subsequent `DumpModeDecode` call then copies from an out-of-bounds
address → OOB read / SIGSEGV.

### How tiffsplit actually copies images

Reading `libtiff/tools/tiffsplit.c` in full reveals that tiffsplit never calls
`TIFFReadScanline`. Its copy logic branches on tile vs strip layout:

```c
// tiffsplit.c line 224-227
if (TIFFIsTiled(in))
    return (cpTiles(in, out));
else
    return (cpStrips(in, out));
```

Both `cpStrips` (lines 230-260) and `cpTiles` (lines 263-293) use the **raw**
strip/tile I/O path:

```c
// cpStrips, line 251
TIFFReadRawStrip(in, s, buf, bytecounts[s])

// cpTiles, line 284
TIFFReadRawTile(in, t, buf, bytecounts[t])
```

`TIFFReadRawStrip` (tif_read.c:218-254) reads raw, uncompressed bytes straight
from the file using `TIFFReadRawStrip1`, which performs a direct file-level read.
It does **not** call any codec function — no `tif_decoderow`, no `tif_seek`,
no `DumpModeDecode`, no `DumpModeSeek`.

### Why the scan-line path never executes

The codec functions (`DumpModeSeek`, `DumpModeDecode`) are only reachable through:

```
TIFFReadScanline → TIFFSeek (tif_read.c:88) → (*tif->tif_seek)() = DumpModeSeek
                 → (*tif->tif_decoderow)()   = DumpModeDecode
```

Since tiffsplit never calls `TIFFReadScanline`, this entire chain is dead code
in the context of tiffsplit.

### Secondary analysis: even if the path were reachable, overflow is still hard

For completeness — if tiffsplit did use scanline I/O — sequential reads still
would not trigger the overflow:

1. `TIFFReadScanline` sets `tif->tif_row = row + 1` after each read
   (tif_read.c:110).
2. On the next call for `row = tif_row`, the `row != tif->tif_row` guard at
   tif_read.c:84 is false, so `DumpModeSeek` is called with `nrows = 0`.
3. `DumpModeSeek` is only called when `row > tif_row`, meaning rows are
   accessed out-of-order. tiffsplit accesses rows 0, 1, 2, ... in strict order.
4. Even with out-of-order access, `nrows * scanlinesize` must exceed 2^32 to
   overflow. With `scanlinesize = 3` (1-pixel-wide RGB), this requires `nrows ≥
   0x55555555` (~1.4 billion), which in turn requires `ImageLength ≥ 0x55555556`
   — infeasible in a small PoC file.

### Source references

| File | Lines | Note |
|------|-------|------|
| libtiff/tools/tiffsplit.c | 224-227 | Branch: tiled vs strip copy |
| libtiff/tools/tiffsplit.c | 244-255 | `cpStrips`: uses `TIFFReadRawStrip` |
| libtiff/tools/tiffsplit.c | 277-285 | `cpTiles`: uses `TIFFReadRawTile` |
| libtiff/libtiff/tif_read.c | 84-91 | `TIFFSeek` → `(*tif->tif_seek)` call site |
| libtiff/libtiff/tif_read.c | 96-117 | `TIFFReadScanline` — never called by tiffsplit |
| libtiff/libtiff/tif_read.c | 218-254 | `TIFFReadRawStrip` — bypasses all codecs |
| libtiff/libtiff/tif_dumpmode.c | 96-101 | `DumpModeSeek` — vulnerable function |

### Conclusion

`DumpModeSeek` is unreachable from `tiffsplit`. The binary exclusively uses
raw-strip/raw-tile I/O, which bypasses the entire decode-codec layer. This PoC
is SKIPPED — the vulnerability cannot be triggered by passing any crafted TIFF
file on the tiffsplit command line.

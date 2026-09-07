# VULN 002 Skip Reason

## Vulnerability

**Title**: Negative linebytes Causes _TIFFmemset OOB Write Before Heap Buffer
**Source**: libtiff/tools/ras2tiff.c, lines 195-200

## Why Skipped

The designated trigger binary for this task is `tiffsplit`, which processes TIFF files on the command line.

The vulnerability resides in `ras2tiff.c`, which is compiled into the separate `ras2tiff` binary. This binary processes **Sun Raster (.ras) files** — a completely different file format from TIFF.

- `tiffsplit` reads TIFF files and splits them into multiple single-image TIFF files.
- `ras2tiff` reads Sun Raster (.ras) files and converts them to TIFF format.
- The vulnerable code path (the `linebytes` integer truncation and subsequent `_TIFFmemset` OOB write) is only reachable via the `ras2tiff` binary's `main()` function in `ras2tiff.c`.
- There is no code path from `tiffsplit`'s TIFF parsing logic into `ras2tiff.c`'s Sun Raster parsing routines.

Both binaries are confirmed to exist in `/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/`, but they are entirely independent executables. Triggering this vulnerability via `tiffsplit` with a crafted TIFF file is not possible.

## Trigger Requirement

To trigger this vulnerability, one would need to pass a crafted Sun Raster `.ras` file directly to the `ras2tiff` binary — not to `tiffsplit`. Since the task constraint requires triggering via `tiffsplit`, this PoC is skipped.

# VULN 001 Skip Reason

## Vulnerability
Heap OOB Read/Write in RGB SWAP Loop via tsize_t Truncation  
Source: `/data/ylwang/non-textfuzz/target/libtiff/tools/ras2tiff.c` (lines 195-218)

## Why SKIPPED

The constrained trigger binary is `tiffsplit`, which accepts TIFF files on the command line. The vulnerability described lives in `ras2tiff`, a completely separate binary that processes Sun Raster (.ras) files.

Confirmed binaries present in `/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/`:
- `ras2tiff` — the vulnerable binary (processes .ras input)
- `tiffsplit` — the permitted trigger binary (processes .tiff input)

These are independent tools with different input formats and different code paths. There is no way to reach the vulnerable code in `ras2tiff` (specifically the `linebytes`/`_TIFFmalloc`/SWAP loop in `main()`) by passing a crafted TIFF file to `tiffsplit`. The two binaries share the libtiff library but the bug is in the `ras2tiff` tool's own `main()` function, not in shared library code reachable from `tiffsplit`.

## Conclusion

A PoC cannot be generated for the specified trigger binary (`tiffsplit`). The vulnerability is only exploitable via the `ras2tiff` binary with a crafted Sun Raster (.ras) input file.

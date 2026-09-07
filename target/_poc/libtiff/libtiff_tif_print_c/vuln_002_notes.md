# VULN 002 - Skip Reason

## Vulnerability
- **Title**: Heap OOB Read in TIFFPrintDirectory via Out-of-Order TRANSFERFUNCTION/BITSPERSAMPLE IFD Tags
- **Function**: TIFFPrintDirectory()
- **File**: libtiff/tif_print.c, lines 478-481
- **CWE**: CWE-125 (Out-of-bounds Read)

## Analysis

The vulnerability is triggered when `TIFFPrintDirectory()` is called with the `TIFFPRINT_CURVES` flag on a TIFF file where the TRANSFERFUNCTION tag (0x012D = 301) appears before the BITSPERSAMPLE tag (0x0102 = 258) in the IFD.

When TRANSFERFUNCTION is processed before BITSPERSAMPLE, the transferfunction arrays are allocated with size `1 << bps_default` = `1 << 1` = 2 entries. After this allocation, BITSPERSAMPLE is processed and set to 16. The subsequent print loop in `TIFFPrintDirectory()` then iterates over `1 << 16` = 65536 entries using the small 2-element arrays, causing a heap out-of-bounds read.

## Why tiffsplit Cannot Trigger This Vulnerability

The `tiffsplit` binary (`/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit`) does **NOT** call `TIFFPrintDirectory()` at any point in its execution.

Verified by:
1. `grep -r "TIFFPrintDirectory" /data/ylwang/non-textfuzz/target/libtiff/tools/tiffsplit.c` - returns no results
2. Reading the full source of `tiffsplit.c` - the function uses only `TIFFOpen`, `TIFFReadDirectory`, `TIFFClose`, `TIFFGetField`, `TIFFSetField`, and strip/tile copy functions. No call to `TIFFPrintDirectory` exists.

The only tool binary that calls `TIFFPrintDirectory()` is `tiffinfo` (in `tools/tiffinfo.c`), which uses it to print directory information when invoked with the `-c` flag (which sets `TIFFPRINT_CURVES`).

## Conclusion

This vulnerability CANNOT be triggered via the `tiffsplit` binary. The correct trigger path is:
```
tiffinfo -c crafted.tif
```

Since the task constraint is to use only `tiffsplit`, and `tiffsplit` does not call `TIFFPrintDirectory()`, this PoC is **SKIPPED**.

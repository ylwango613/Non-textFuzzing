# VULN 001 - Skip Notes

## Vulnerability
- **Title**: Heap OOB Read in TIFFPrintDirectory via Out-of-Order COLORMAP/BITSPERSAMPLE IFD Tags
- **Function**: TIFFPrintDirectory() in libtiff/tif_print.c (lines 464-470)
- **CWE**: CWE-125 (Out-of-bounds Read)

## Skip Reason

The vulnerability exists in the function `TIFFPrintDirectory()` which is defined in
`/data/ylwang/non-textfuzz/target/libtiff/libtiff/tif_print.c`.

Investigation of the `tiffsplit` source code
(`/data/ylwang/non-textfuzz/target/libtiff/tools/tiffsplit.c`)
confirms that `tiffsplit` does **not** call `TIFFPrintDirectory()` anywhere.

`tiffsplit` only:
- Opens the input TIFF via `TIFFOpen()`
- Copies directory metadata via `TIFFGetField()` / `TIFFSetField()` calls in `tiffcp()`
- Copies strip/tile data via `TIFFReadRawStrip()` / `TIFFWriteRawStrip()` (and tile equivalents)
- Closes files via `TIFFClose()`

The only libtiff tool that calls `TIFFPrintDirectory()` is `tiffinfo`
(in `/data/ylwang/non-textfuzz/target/libtiff/tools/tiffinfo.c`), which is invoked
with the `-c` flag to pass the `TIFFPRINT_COLORMAP` flag.

## Conclusion

Since `tiffsplit` never invokes `TIFFPrintDirectory()`, a crafted TIFF file passed to
`tiffsplit` cannot reach the vulnerable code path. The PoC would need to target
`tiffinfo -c crafted.tif` instead of `tiffsplit`. No PoC files are generated for the
`tiffsplit` binary.

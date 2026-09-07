# VULN 001 - Skip Reason

**Title**: Integer Overflow in `uncompr_size` Leads to Heap Under-Allocation and OOB Memory Access

**Status**: SKIPPED

## Reason

The vulnerability is located in `bmp2tiff.c` (lines 591-598, 687-694), which is part of the `bmp2tiff` tool. This tool converts BMP files to TIFF format and contains a vulnerable RLE decode path where an integer overflow in `uncompr_size` can lead to heap under-allocation and out-of-bounds memory access.

The only allowed trigger binary for this project is `tiffsplit`, located at:
`/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit`

`tiffsplit` is a completely separate tool that splits multi-image TIFF files into individual TIFF files. It does not process BMP files and has no code path that reaches `bmp2tiff.c`'s vulnerable RLE decode logic.

There is no way to trigger this vulnerability by passing a crafted TIFF file to `tiffsplit` on the command line. The vulnerable code exists only in the `bmp2tiff` binary (confirmed present at `/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/bmp2tiff`), which is outside the scope of allowed trigger binaries.

## Conclusion

This vulnerability cannot be demonstrated using only `tiffsplit`. A PoC would require either:
1. Using the `bmp2tiff` binary directly (not allowed per hard rules), or
2. Modifying source code to expose the vulnerable path (not allowed per hard rules).

Therefore, no `_run.sh` or `_result.txt` are generated for this vulnerability.

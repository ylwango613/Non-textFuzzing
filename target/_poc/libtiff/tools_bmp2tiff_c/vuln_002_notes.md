# VULN 002 — Skip Reason

**Title**: Heap OOB Read in RLE8 Decompression Loop (Off-by-One on `comprbuf`)

**Location**: `bmp2tiff.c`, lines 620-622

## Why This Vulnerability Is Skipped

The vulnerable code resides in `bmp2tiff.c`, which implements the `bmp2tiff` tool. This tool reads BMP files and converts them to TIFF. The heap out-of-bounds read occurs during RLE8 decompression of a crafted BMP input.

The only permitted trigger binary for this project is `tiffsplit`, which:
- Accepts TIFF files as input (not BMP files)
- Has no code path that invokes or reaches the BMP RLE8 decompression logic in `bmp2tiff.c`
- Is a completely separate tool from `bmp2tiff`

There is no way to craft a TIFF file and pass it to `tiffsplit` such that the vulnerable RLE8 decompression loop in `bmp2tiff.c` (lines 620-622) is reached. The two tools share only the libtiff library; the BMP parsing and decompression code is exclusive to `bmp2tiff`.

Note: the `bmp2tiff` binary does exist at `/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/bmp2tiff`, but using it is not permitted by the hard rules of this task.

## Conclusion

This vulnerability cannot be triggered by passing a crafted TIFF file to `tiffsplit` on the command line. PoC generation is therefore skipped.

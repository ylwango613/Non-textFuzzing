# VULN 001 - Skipped

## Vulnerability Summary

- **Title:** Integer Overflow in bufsize Calculation Leading to Heap Buffer Overflow
- **Location:** `main()` in `libtiff/tools/raw2tiff.c`, lines 263-299
- **Status:** SKIPPED

## Reason for Skipping

The only allowed binary for triggering PoCs in this project is:

    /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit

This vulnerability **cannot** be triggered by passing a crafted TIFF file to `tiffsplit` for the following reasons:

1. **Different binary, different code path.** The vulnerable code lives in `raw2tiff.c`'s `main()` function, which is compiled into the `raw2tiff` executable. `tiffsplit` is a completely separate binary compiled from `tiffsplit.c`. At no point does `tiffsplit` call or share code with `raw2tiff`'s `main()`.

2. **Vulnerability requires raw2tiff-specific CLI options.** The integer overflow is triggered only when `raw2tiff` is invoked with specific command-line arguments such as `-w 1073741825 -b 1 -d long -i band`. These options are parsed and acted upon solely within `raw2tiff`'s `main()` function and are meaningless to `tiffsplit`.

3. **tiffsplit is a TIFF reader/splitter, not a raw-data converter.** `tiffsplit` reads an existing TIFF file and splits it into per-directory TIFF files. It does not perform raw-to-TIFF conversion, does not compute `bufsize` from width/height/depth parameters, and therefore never reaches the vulnerable arithmetic.

4. **No shared library surface.** The vulnerable calculation is not exposed through any libtiff library function that `tiffsplit` would invoke when processing a TIFF file. A crafted TIFF input to `tiffsplit` cannot redirect execution into `raw2tiff`'s `main()`.

## Conclusion

Because the vulnerable code path is exclusively reachable through the `raw2tiff` binary using specific command-line flags, and the only permitted binary is `tiffsplit`, this PoC is skipped.

# VULN 002 - Skipped

## Title
NULL Pointer Dereference Due to Missing malloc Return Value Check

## Location
`main()` in `libtiff/tools/raw2tiff.c`, lines 264-272, 288, 304

## Why This Vulnerability Is Skipped

The vulnerable code resides entirely in `raw2tiff.c`'s `main()` function, which belongs to the `raw2tiff` binary. The only binary permitted for triggering PoCs in this audit is:

    /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit

`tiffsplit` and `raw2tiff` are two completely separate tools built from separate source files. `tiffsplit` reads existing TIFF files and splits them; `raw2tiff` converts raw image data into TIFF format. They do not share a `main()` function and `tiffsplit` does not link against or execute any code from `raw2tiff.c`.

The NULL dereference requires all of the following conditions to hold simultaneously:

1. `malloc()` returns NULL (allocation failure) during the buffer setup inside `raw2tiff`'s `main()` at lines 264-272.
2. The result of that failed allocation is passed without a NULL check to `read()` at lines 288 and 304.
3. These conditions are triggered via `raw2tiff`-specific command-line options (`-w <large value>`, `-b <bits>`, `-d <datatype>`) that only exist in the `raw2tiff` argument parser.

There is no TIFF file format payload that can cause `tiffsplit` to execute the code path in `raw2tiff.c`. `tiffsplit` only reads and parses TIFF structures; it never calls into `raw2tiff`'s `main()` or its buffer allocation logic.

## Conclusion

Because the vulnerability cannot be triggered by passing a crafted TIFF file to `tiffsplit` on the command line, this PoC is marked **SKIPPED**.

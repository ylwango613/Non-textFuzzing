# VULN 002 - Skipped

## Vulnerability Details

- **Name:** Global BSS OOB Write in readraster() via Unvalidated datasize Causes Init Loop Overflow
- **Function:** readraster() in tools/gif2tiff.c (lines 331-341)
- **Attack vector:** Crafted GIF file
- **Trigger path:** main() -> convert() -> readgifimage() -> readraster()
- **Trigger condition:** LZW minimum code size byte set to 13 or larger in a GIF file

## Reason for Skipping

This vulnerability is in `gif2tiff.c`, specifically in the `readraster()` function which reads and processes GIF LZW compressed image data. Triggering the vulnerability requires:

1. A `gif2tiff` binary that can parse and process GIF files.
2. A crafted GIF file with a malformed LZW minimum code size byte (value >= 13).

The only allowed binary available for PoC testing is:

```
/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit
```

`tiffsplit` is a TIFF processing utility. It reads and splits multi-page TIFF files; it has no code path that leads to gif2tiff's `readraster()`, `readgifimage()`, or `convert()` functions. There is no mechanism by which a crafted input to `tiffsplit` can reach the vulnerable GIF LZW parsing logic in `gif2tiff.c`.

A `gif2tiff` binary built from the same libtiff source tree would be required to trigger this vulnerability. Since no such binary is available and tiffsplit cannot be used as a substitute, this vulnerability cannot be demonstrated and must be skipped.

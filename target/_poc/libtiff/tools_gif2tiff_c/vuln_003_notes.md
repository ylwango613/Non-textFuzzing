# VULN 003 - Global BSS OOB Write in process() via Unbounded avail Exceeding Array Bounds

## Status: SKIPPED

## Reason

This vulnerability is in `tools/gif2tiff.c`, specifically in the `process()` function (lines 417-419, 421), which is part of the GIF-to-TIFF conversion tool `gif2tiff`. The trigger path is:

```
main() -> convert() -> readgifimage() -> readraster() -> process()
```

The vulnerability is triggered by providing a crafted GIF file containing approximately 4090 LZW codes that generate new dictionary entries without sending clear or EOI codes, causing the `avail` variable to increment past 4095 and write out of bounds into the global BSS array.

## Why It Cannot Be Triggered

The only available binary for testing is:

```
/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit
```

`tiffsplit` is a tool that splits multi-directory TIFF files into separate TIFF files. It processes TIFF format input, not GIF format input. There is no code path from `tiffsplit` through any of the gif2tiff functions (`process()`, `readraster()`, `readgifimage()`, `convert()`).

To trigger VULN 003, a `gif2tiff` binary would be required. Without access to a `gif2tiff` binary, there is no mechanism to pass a crafted GIF file through the vulnerable code path. Therefore, this vulnerability cannot be demonstrated with the available tooling and must be skipped.

# VULN 001 - Skipped

## Vulnerability Summary

- **Name:** Heap Buffer Overflow in LZW Output via Missing Per-Write Bounds Check in process()
- **Functions:** process(), readraster()
- **Lines:** 355-364, 426-428
- **Source file:** tools/gif2tiff.c
- **Attack vector:** Crafted GIF file
- **Trigger path:** main() -> convert() -> readgifimage() -> readraster() -> process()

## Reason for Skipping

This vulnerability resides in `tools/gif2tiff.c`, which is part of the `gif2tiff` utility. The `gif2tiff` tool accepts GIF files as input and converts them to TIFF format. The vulnerable code path is only reachable when `gif2tiff` processes a malformed GIF file.

The only available binary for PoC testing in this audit is:

```
/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit
```

`tiffsplit` is a separate libtiff utility that splits multi-image TIFF files into individual TIFF files. It accepts TIFF files as input and contains no code that calls or shares any code path with the vulnerable `process()` or `readraster()` functions defined in `gif2tiff.c`.

There is no code path from `tiffsplit` to the vulnerable `gif2tiff.c` functions. A crafted TIFF file passed to `tiffsplit` cannot reach `process()` or `readraster()` in `gif2tiff.c` under any circumstances.

## Conclusion

Because the vulnerability cannot be triggered by passing a crafted TIFF file on the command line to `tiffsplit`, this vulnerability is **SKIPPED** per the defined skip condition.

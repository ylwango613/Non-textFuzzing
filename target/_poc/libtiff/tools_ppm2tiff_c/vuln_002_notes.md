# VULN 002 - Skipped

## Vulnerability Summary

**Type:** Null Pointer Dereference via Negative `linebytes` Passed to `_TIFFmalloc`
**Location:** `libtiff/tools/ppm2tiff.c`, lines 228-243, `main()` function
**Tool:** `ppm2tiff`

## Why This Vulnerability Is Skipped

### Trigger Requirements

This vulnerability requires:

1. Running the `ppm2tiff` binary (not `tiffsplit` or any other libtiff tool).
2. Providing a crafted PPM file (P6/RGB format) as input — specifically a PPM with an image width `w >= 2147483648` (when `spp=3`) or `w >= 2147483649` (when `spp=1`).
3. The oversized width causes integer overflow when computing `linebytes = spp * w`, producing a negative (or zero) value, which is then passed to `_TIFFmalloc`, resulting in a null pointer dereference.

### Constraint Preventing Exploitation

The only allowed binary for PoC generation is:

```
/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit
```

`tiffsplit` is a TIFF-to-TIFF splitting tool. It:
- Accepts TIFF files as input, not PPM files.
- Does not invoke the `ppm2tiff` code path at all.
- Cannot be made to reach `ppm2tiff.c`'s `main()` function or the vulnerable `linebytes` computation.

### Conclusion

Because the vulnerable code path exists exclusively in `ppm2tiff.c`'s `main()` function and can only be reached by running the `ppm2tiff` binary with a specially crafted PPM input, and because the only permitted binary (`tiffsplit`) processes TIFF files through an entirely separate code path, **this vulnerability cannot be triggered under the given constraints**.

No `vuln_002_gen.py` or `vuln_002_run.sh` are produced for this entry.

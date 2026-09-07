# VULN 003 - Skip Reason

## Vulnerability
NULL Pointer Dereference in TIFFPrintDirectory Transfer Function Print via
Out-of-Order EXTRASAMPLES/TRANSFERFUNCTION IFD Tags

- **Function**: TIFFPrintDirectory() in libtiff/tif_print.c, lines 482-484
- **CWE**: CWE-476 (NULL Pointer Dereference)

## Analysis

The vulnerability is triggered only when `TIFFPrintDirectory()` is called with
the `TIFFPRINT_CURVES` flag on a TIFF file crafted with:
- SAMPLESPERPIXEL=3
- EXTRASAMPLES (tag 0x0152) appearing before TRANSFERFUNCTION (tag 0x012D) in
  the IFD (out-of-order by tag number)
- TRANSFERFUNCTION allocated with count=2 only, leaving td_transferfunction[1]
  and td_transferfunction[2] as NULL

The inner loop at lines 482-484 then iterates i from 1 to samplesperpixel-1
and dereferences td_transferfunction[i] which is NULL, causing SIGSEGV.

## Why tiffsplit Cannot Trigger This

`tiffsplit` (tools/tiffsplit.c) does NOT call `TIFFPrintDirectory()` anywhere.
The binary only:
1. Opens the input TIFF with TIFFOpen()
2. Copies IFD tags field by field using TIFFGetField/TIFFSetField
3. Copies raw strip/tile image data
4. Closes files

The call to `TIFFPrintDirectory()` is present only in `tools/tiffinfo.c`. The
external trigger path described in the vulnerability report (`tiffinfo -c crafted.tif`)
requires the `tiffinfo` binary, not `tiffsplit`.

Since the task constraints restrict use of binaries to
`/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit`, and
`tiffsplit` never calls `TIFFPrintDirectory()`, this vulnerability cannot be
triggered through the permitted binary. No PoC is created.

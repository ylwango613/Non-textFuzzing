# VULN 002 — Heap OOB Read (CMAP pcol unchecked against PCLR numchans)

## Vulnerability Summary

- **File:** `src/libjasper/jp2/jp2_dec.c`, lines 372 and 377
- **Type:** Heap out-of-bounds read
- **Root Cause:** When a CMAP entry has `mtyp == JP2_CMAP_PALETTE` (value 1), the decoder uses `cmapent->pcol` as a column index into `pclrd->lutdata` and `pclrd->bpc` without validating that `pcol < pclrd->numchans`. If `pcol` exceeds `numchans`, the reads go past the end of the allocated arrays.

## PoC Approach

The crafted JP2 file contains:

1. **PCLR box** — Declares a palette with `numchans=1` (NPC=1) and 4 LUT entries. This allocates arrays of size 1 for `lutdata` columns and `bpc` entries.
2. **CMAP box** — Contains one channel-mapping entry with `mtyp=1` (JP2_CMAP_PALETTE) and `pcol=200`. Since `pcol=200 >= numchans=1`, the decoder reads 200 entries past the end of both `pclrd->lutdata` and `pclrd->bpc` on lines 372 and 377 of `jp2_dec.c`.

The `pclr` box is placed before `cmap` inside the `jp2h` superbox to ensure JasPer parses the palette before the channel map, triggering the vulnerable code path during JP2 header decoding.

## Expected ASAN Output

With AddressSanitizer enabled, the binary should report:

```
ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size N at 0x... thread T0
    #0 ... jp2_getdata (jp2_dec.c:372 or jp2_dec.c:377)
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow jp2_dec.c:372 (or :377)
```

The crash/OOB read occurs during `jp2_getdata()` when it processes the CMAP entries and dereferences the palette column `pcol=200` on a buffer sized for only 1 channel.

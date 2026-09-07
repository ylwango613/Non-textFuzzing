# VULN_001 PoC Notes

## Vulnerability Summary

**Function**: `TIFFWriteRationalArray()` in `libtiff/tif_dirwrite.c` line 1017  
**CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap-Based Buffer Overflow) / CWE-476 (NULL Dereference)

The vulnerable line is:
```c
t = (uint32*) _TIFFmalloc(2 * dir->tdir_count * sizeof (uint32));
```

When `dir->tdir_count >= 0x80000000`, the expression `2 * dir->tdir_count` is computed in
**32-bit unsigned arithmetic** (`int * uint32 = uint32`), wrapping around to a tiny value.

For example with `dir->tdir_count = 0x80000001`:
- `2 * 0x80000001 = 0x100000002` wraps to `0x00000002` (uint32)
- `0x00000002 * sizeof(uint32) = 8` — so `_TIFFmalloc(8)` succeeds
- The loop then immediately dereferences `v[0]` where `v = fp = NULL` → **NULL pointer dereference**

## Attack Chain (Theoretical)

```
tiffsplit
  → TIFFOpen("r") on crafted TIFF
  → TIFFReadDirectory()
      → unknown RATIONAL tag with count=0x80000001 found
      → _TIFFCreateAnonFieldInfo() registers it as RATIONAL/VARIABLE2/passcount=TRUE
      → TIFFFetchNormalTag() called
          → _TIFFCheckMalloc(0x80000001, sizeof(float)) — tries to alloc ~8 GB → FAILS
          → ok=0 → TIFFSetField() NOT called → tag NOT stored in td_customValues
  → tiffcp() copies image to output TIFF
  → TIFFClose(out) → TIFFWriteDirectory()
      → iterates td_customValues — empty for this tag (never stored)
      → TIFFWriteRationalArray() is NOT reached
```

## Why the PoC Is SKIPPED

The critical blocker is in `TIFFFetchNormalTag()` (tif_dirread.c line 1670):
```c
cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count, sizeof(float), mesg);
ok = cp && TIFFFetchRationalArray(tif, dp, (float*) cp);
```

For `dp->tdir_count = 0x80000001` on a 64-bit system:
- `bytes = 0x80000001 × 4 = ~8 GB`
- The allocation fails on any typical system (insufficient virtual or physical memory)
- `ok = 0` → `TIFFSetField()` is **never called**
- The unknown tag is **never stored** in `td->td_customValues`
- Therefore `TIFFWriteDirectory()` never writes this tag and never calls `TIFFWriteRationalArray()` with the large count

The minimum count to trigger the 32-bit overflow (`dir->tdir_count ≥ 0x80000000`) requires reading
at minimum `0x80000000 × 4 = 2 GB` of float data from the file. This exceeds practical limits.

### Additionally: tiffsplit does not copy custom/unknown tags

Even if the tag were somehow stored in `in->tif_dir.td_customValues`, tiffsplit's `tiffcp()`
only explicitly copies a fixed list of known tags (via `CopyField` macros). Unknown/custom
RATIONAL tags are **not forwarded** from input to output. Therefore TIFFWriteDirectory on
the output TIFF would not write them regardless.

## Triggering the Bug (Would Require)

To actually trigger this vulnerability one would need to either:
1. **Programmatic access**: Register a custom RATIONAL VARIABLE2 tag at runtime using
   `TIFFMergeFieldInfo()`, call `TIFFSetField()` with count=0x80000001, have the internal
   `_TIFFVSetField` malloc fail, then call `TIFFWriteDirectory()`.
2. **Extreme memory**: A system where 8 GB allocations succeed (16+ GB RAM with overcommit)
   and the input TIFF actually contains ~16 GB of RATIONAL data bytes.

## PoC Approach

The crafted TIFF file (`vuln_001.tif`) contains:
- A minimal 1×1 grayscale TIFF to satisfy baseline requirements
- An unknown RATIONAL tag (0xFFE9) with count=0x80000001 and data offset=0

The file is valid enough to open; tiffsplit will encounter the huge-count RATIONAL tag, log
an allocation-failure warning, and complete without crashing.

## Expected Behavior

When running `tiffsplit vuln_001.tif`:
- libtiff prints a warning about failing to allocate memory for the RATIONAL array
- tiffsplit successfully copies the image data (1 strip of 1 byte)
- **No crash** occurs because the tag never reaches `TIFFWriteRationalArray()`
- ASAN/UBSAN do **not** fire

## Status: SKIPPED

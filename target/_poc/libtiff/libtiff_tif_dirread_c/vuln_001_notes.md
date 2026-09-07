# VULN 001 — EstimateStripByteCounts Integer Overflow

## Vulnerability location

File: `libtiff/libtiff/tif_dirread.c`, line 1015  
Function: `EstimateStripByteCounts()`

```c
cc = cc * dp->tdir_count;   // line 1015 — uint32 * uint32, no overflow check
```

## Root cause

`TIFFDataWidth(TIFF_LONG)` returns 4. When `dp->tdir_count = 0x40000000`,
the product `4 * 0x40000000 = 0x100000000` cannot be represented in uint32 and
wraps to 0. The subsequent check `if (cc > sizeof(uint32))` is then false, so
the loop body does not add any space for this entry. This corrupts the `space`
variable used to estimate per-strip byte counts for strips that lack a
StripByteCounts IFD tag.

## Trigger conditions

1. Compression is not NONE (LZW = 5 used here) — ensures the overflowing code
   path at line 997 (`td->td_compression != COMPRESSION_NONE`) is taken.
2. StripByteCounts tag (0x0117) is absent from the IFD — forces libtiff to call
   `EstimateStripByteCounts()` rather than reading real byte counts.
3. An IFD entry with `tdir_type = TIFF_LONG (4)` and
   `tdir_count = 0x40000000` is present — this is the entry that triggers the
   overflow on line 1015.

## PoC approach

`vuln_001_gen.py` crafts a minimal little-endian TIFF:
- Header pointing to IFD at offset 8.
- IFD with 9 entries covering the minimum required tags plus the overflow
  trigger entry (tag 0xFFFF, type LONG, count 0x40000000).
- StripByteCounts (0x0117) intentionally omitted.
- 8 bytes of fake strip data appended after the IFD.

## Trigger path

```
tiffsplit main()
  -> TIFFOpen()
    -> TIFFReadDirectory()
      -> EstimateStripByteCounts()   <- overflow at line 1015
```

## Expected behavior

With ASAN+UBSAN enabled the unsigned integer overflow (technically defined
behavior in C for unsigned types, but UBSAN with `-fsanitize=unsigned-integer-overflow`
will flag it) or subsequent memory misuse from the wrong strip byte count
estimation should produce a sanitizer report. The inflated/wrong strip byte
count may also cause an out-of-bounds read when tiffsplit attempts to process
the strips.

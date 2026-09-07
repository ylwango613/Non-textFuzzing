# VULN 001: NeXTDecode OOB Read — PoC Notes

## Vulnerability

**File**: `libtiff/libtiff/tif_next.c`  
**Function**: `NeXTDecode()`  
**Line**: 69  
**CWE**: CWE-125 (Out-of-bounds Read)

`NeXTDecode` reads the per-scanline type byte unconditionally at line 69:

```c
n = *bp++, cc--;
```

If the raw compressed buffer is already exhausted (`cc == 0`) when the outer loop
still expects another scanline (`occ > 0`), this performs a 1-byte out-of-bounds read.
`cc` then wraps to `-1` (signed `tsize_t`).  Inside the default run-length branch the
only guard is `if (cc == 0) goto bad;` at line 119.  With `cc == -1` that check is
always false, enabling continued OOB reads until a crash.

## PoC Design

### File: `vuln_001.tif`

| Field | Value | Reason |
|---|---|---|
| ImageWidth | 1024 | Forces first scanline to consume exactly 1024 input bytes |
| ImageLength | 2 | Two scanlines; outer loop runs twice |
| RowsPerStrip | 2 | Both scanlines in one strip |
| Compression | 32766 | NeXT compression |
| FillOrder | 2 (LSB2MSB) | Bypasses mmap shortcut in `TIFFFillStrip`; forces heap allocation |
| StripByteCounts | 1024 | Heap buffer = exactly 1024 bytes; ASAN red zone at byte 1024 |
| Strip data | 1024 × 0x80 | After `TIFFReverseBits`: 1024 × 0x01 (one pixel per code byte) |

### Why FillOrder=2 is required

Without `FillOrder=2`, libtiff takes the mmap shortcut in `TIFFFillStrip`:

```c
if (isMapped(tif) && (isFillOrder(tif, td->td_fillorder) || ...)) {
    tif->tif_rawdata = tif->tif_base + td->td_stripoffset[strip];
}
```

`isFillOrder()` is `(tif->tif_flags & fillorder_tag) != 0`.  The default library
flag is `FILLORDER_MSB2LSB = 1`.  With the TIFF's `FillOrder` tag = 2, the bitwise
AND is 0 → `isFillOrder()` returns false → the heap path is taken instead:

```c
_TIFFmalloc(TIFFroundup(bytecount, 1024))   // = 1024 bytes exactly
```

ASAN tracks this allocation precisely and poisons byte 1024 (the right red zone).

### Decode trace (first scanline, imagewidth=1024)

Strip bytes in file: `0x80 * 1024`.  After `TIFFReverseBits`: `0x01 * 1024`.

- **Outer loop iteration 1** (`occ = 256 > 0`):
  - Type byte read (line 69): `n = 0x01`, `cc = 1023`
  - `default` case: `grey=0`, `count=1` → fill pixel 0
  - Inner loop reads 1023 more `0x01` bytes, fills pixels 1–1023
  - `npixels = 1024 >= imagewidth(1024)` → break; `cc = 0`
  - `occ -= tif_scanlinesize(128)` → `occ = 128`

- **Outer loop iteration 2** (`occ = 128 > 0`):
  - Line 69: `n = *bp++` — reads `tif_rawdata[1024]` which is in the ASAN red zone
  - **→ AddressSanitizer: heap-buffer-overflow, READ of size 1**

## Trigger Tool

`tiffsplit` uses `TIFFReadRawStrip()` which reads the compressed stream directly
without calling `NeXTDecode`.  The decode path requires `TIFFReadEncodedStrip()`,
so `tiffcp` is used instead:

```
tiffcp main() -> tiffcp() -> cpDecodedStrips() -> TIFFReadEncodedStrip()
    -> TIFFFillStrip() -> TIFFStartStrip() -> NeXTDecode()
```

## ASAN Report (excerpt)

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x519000000e80
READ of size 1 at 0x519000000e80 thread T0
    #0 in NeXTDecode  tif_next.c:69
    #1 in TIFFReadEncodedStrip
    #2 in cpDecodedStrips
    #3 in tiffcp main

0x519000000e80 is located 0 bytes to the right of 1024-byte region
[0x519000000a80, 0x519000000e80)
allocated by: _TIFFmalloc <- TIFFReadBufferSetup <- TIFFFillStrip
```

## Status

`VERIFIED_CRASH` — reproducible heap-buffer-overflow confirmed by ASAN.

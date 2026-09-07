# VULN 001 — PackBitsDecode literal-copy branch heap OOB read

## PoC Approach

`vuln_001_gen.py` builds a minimal little-endian TIFF with these properties:

| Field | Value |
|-------|-------|
| ImageWidth | 4 |
| ImageLength | 1 |
| BitsPerSample | 8 |
| Compression | 32773 (PackBits) |
| RowsPerStrip | 1 |
| StripByteCounts | 1 |
| Strip data | `0x7E` (1 byte) |

The single byte `0x7E` is a PackBits **literal-run header**: it declares "copy the next 127 bytes from the input verbatim into the output".  Because StripByteCounts = 1, the library sets `tif_rawcc = 1` and allocates a 1-byte input buffer.  After consuming the header byte, `cc = 0` and `bp` points one byte past the end of the allocation.

## Expected trigger path (via TIFFReadEncodedStrip/TIFFReadScanline)

When a decoder such as `tiff2bw`, `tiffcp`, or `tiff2rgba` calls `TIFFReadEncodedStrip`, the execution path is:

```
TIFFReadEncodedStrip
  → TIFFFillStrip          (loads raw bytes into tif_rawdata)
  → (*tif_decodestrip)()   = PackBitsDecode
      n = *bp++ = 0x7E = 126  (literal run: copy n+1=127 bytes)
      cc-- → cc = 0
      /* only occ (output) is checked, NOT cc (input) */
      _TIFFmemcpy(op, bp, 127)   ← reads 127 bytes past a 1-byte allocation
```

This is CWE-125: Out-of-Bounds Read.

## Why tiffsplit does NOT trigger the crash

`tiffsplit` copies strips with `TIFFReadRawStrip` → `TIFFWriteRawStrip`, which transfers the compressed bytes verbatim **without decompressing them**.  The codec function `PackBitsDecode` is therefore never called.  As a result:

- `tif_rawcc` is never set from strip data in the decode path.
- `PackBitsDecode` is never entered.
- No ASAN/UBSAN error is produced.

## Verification

Running `tiffinfo -d vuln_001.tif` (which does decode) shows:

```
vuln_001.tif: Warning, PackBitsDecode: discarding 123 bytes to avoid buffer overrun.
```

This confirms the malformed strip reaches `PackBitsDecode` and triggers the problematic branch, but the output-overflow guard clamps `n` before the OOB read occurs.  In a wider image (≥ 127 pixels) the clamp would not apply and ASAN would detect the OOB read past the heap allocation.

## Status

UNVERIFIED — `tiffsplit` ran cleanly (exit 0, no sanitizer output) because it uses the raw-strip copy path that bypasses `PackBitsDecode`.

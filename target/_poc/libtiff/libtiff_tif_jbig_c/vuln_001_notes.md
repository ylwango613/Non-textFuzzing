# VULN-001: JBIGDecode ignores size parameter — heap-buffer-overflow

## Root Cause

`JBIGDecode()` in `tif_jbig.c` line 82 explicitly discards the `size` parameter
(the byte capacity of `buffer`):

```c
(void) size, (void) s;
```

At line 125 it copies the fully-decoded JBIG image into `buffer` using the
decoder-reported size rather than the caller-supplied capacity:

```c
_TIFFmemcpy(buffer, pImage, jbg_dec_getsize(&decoder));
```

`jbg_dec_getsize()` returns a value derived from the BIE header embedded in the
attacker-controlled compressed strip data.  The TIFF IFD dimensions (which
control how much heap is allocated for `buffer`) are completely ignored.

## Trigger Path

```
tiffcp -c none
  -> cpDecodedStrips()
  -> TIFFReadEncodedStrip(tif, strip, buf, size=8)
  -> TIFFFillStrip()
  -> JBIGDecode(tif, buf, 8, ...)
     line 125: _TIFFmemcpy(buf, pImage, 8192)   ← overflow of 8184 bytes
```

## PoC Design

| Field            | Value     | Effect |
|------------------|-----------|--------|
| IFD ImageWidth   | 8         | `TIFFVStripSize()` → `buffer` alloc = 8 bytes |
| IFD ImageLength  | 8         |  |
| IFD Compression  | 34661     | JBIG codec selected |
| IFD FillOrder    | 2 (LSB→MSB) | Prevents `TIFFReverseBits()` inside `JBIGDecode` from corrupting BIE |
| BIE X_D          | 256       | `jbg_dec_getsize()` → 8192 bytes |
| BIE Y_D          | 256       |  |

## Why tiffsplit Cannot Trigger This

`tiffsplit` calls `TIFFReadRawStrip()` (tools/tiffsplit.c ~line 251) which
copies the compressed bytes verbatim without invoking any codec.  `JBIGDecode`
is never called.  `tiffcp -c none` forces a transcode through
`cpDecodedStrips()` → `TIFFReadEncodedStrip()` → `JBIGDecode` and IS the
correct trigger.  Both binaries are in the same ASAN+UBSAN build.

## Non-obvious Detail: FillOrder

By default libtiff uses `FILLORDER_MSB2LSB=1`.  `JBIGDecode` (lines 84-87):

```c
if (isFillOrder(tif, tif->tif_dir.td_fillorder))
    TIFFReverseBits(tif->tif_rawdata, tif->tif_rawdatasize);
```

`isFillOrder(tif, 1)` evaluates to TRUE (bit 0 of `tif_flags` is always set for
MSB2LSB), so the raw strip bytes are bit-reversed before `jbg_dec_in` sees them.
This scrambles `X_D`/`Y_D` in the BIE header → `jbg_dec_in` hits its memory
guard and returns `JBG_ENOMEM` instead of `JBG_EOK`, so the memcpy is skipped.

Setting `FillOrder=2` in the IFD makes `isFillOrder(tif, 2)` return FALSE,
so the BIE reaches `jbg_dec_in` intact and the overflow is reached.

## Expected ASAN Output

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8192 at ...
  #0 __interceptor_memcpy
  #1 _TIFFmemcpy
  #2 JBIGDecode       (tif_jbig.c:125)
  #3 TIFFReadEncodedStrip
```

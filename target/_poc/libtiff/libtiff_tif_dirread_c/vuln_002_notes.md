# VULN 002 — Integer Overflow in TIFFFetchNormalTag()

## Vulnerable code

File: `libtiff/tif_dirread.c`, line 1690

```c
case TIFF_ASCII:
case TIFF_UNDEFINED:
    cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count + 1, 1, mesg);
```

`dp->tdir_count` is `uint32_t`. When its value is `0xFFFFFFFF` (UINT32_MAX),
the expression `dp->tdir_count + 1` wraps around to `0` in unsigned 32-bit
arithmetic. The wrapped value 0 is then passed to `_TIFFCheckMalloc` as the
element count.

## Trigger path

```
tiffsplit main()
  -> TIFFOpen()
  -> TIFFReadDirectory()
     -> TIFFFetchNormalTag()  (for each non-special IFD tag)
        -> line 1690: _TIFFCheckMalloc(tif, 0xFFFFFFFF + 1, 1, mesg)
                                              ^^^^^^^^^^^^^^^^^ wraps to 0
```

## PoC approach

The crafted TIFF file (`vuln_002.tif`) contains a minimal valid image
(1x1 pixel, 8-bit grayscale) plus an `ImageDescription` IFD entry
(tag 0x010E, type ASCII) with `tdir_count = 0xFFFFFFFF`.

Key design choices:
- `tdir_count = 0xFFFFFFFF` satisfies the `> 1` check at line 1646, entering
  the array-of-values branch that leads to the vulnerable ASCII case.
- The tag `ImageDescription` has `field_readcount = TIFF_VARIABLE` in the
  libtiff field table, so `CheckDirCount` with a fixed expected count of 1
  is NOT invoked before reaching the vulnerable line.
- The value/offset field of the IFD entry points to the strip data area,
  which is a safe location within the file (prevents an out-of-bounds read
  before reaching the overflow site).

## Expected behavior

On 64-bit systems, `_TIFFCheckMalloc` receives `nmemb=0` after the overflow.
The implementation detects the zero size and returns NULL without allocating
memory — so no heap corruption occurs. The integer overflow itself is the
defect: a wrong (zero) allocation size is silently requested.

Because:
1. Unsigned integer overflow is defined behavior in C (no UBSan report).
2. `_TIFFCheckMalloc` gracefully handles the 0-size request.

ASAN/UBSan are not expected to emit errors. The status is UNVERIFIED —
the code path is reached but no sanitizer fires.

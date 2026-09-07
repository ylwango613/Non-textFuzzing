# PoC Notes: libtiff TIFFSetupStrips() Integer Overflow (VULN_001)

## Vulnerability Summary

File: `libtiff/libtiff/tif_write.c`, lines 458–469, function `TIFFSetupStrips()`

```c
td->td_stripoffset = (uint32 *)
    _TIFFmalloc(td->td_nstrips * sizeof (uint32));
td->td_stripbytecount = (uint32 *)
    _TIFFmalloc(td->td_nstrips * sizeof (uint32));
```

`_TIFFmalloc` accepts `tsize_t`, which is `int32` in this build (confirmed in
`libtiff/libtiff/tiffio.h` line 67: `typedef int32 tsize_t;`).

When `td->td_nstrips = 0x40000001`:
- `0x40000001 * sizeof(uint32)` = `0x40000001 * 4` = `0x100000004` (as `size_t`)
- Implicitly cast to `int32` = `4`
- `_TIFFmalloc(4)` succeeds — allocates only 4 bytes (1 `uint32` slot)
- `td->td_nstrips` remains `0x40000001`
- Later writes to `td_stripoffset[1]` etc. are heap-buffer-overflow

## Why the Vulnerability CANNOT Be Triggered via tiffsplit

### Read-side protection in `_TIFFCheckRealloc`

When libtiff opens (reads) a TIFF input, strip arrays are allocated via
`_TIFFCheckMalloc` → `_TIFFCheckRealloc` (`tif_aux.c` lines 36–56):

```c
tsize_t bytes = nmemb * elem_size;   // tsize_t = int32
if (nmemb && elem_size && bytes / elem_size == nmemb)
    cp = _TIFFrealloc(buffer, bytes);
```

With `nmemb = 0x40000001` and `elem_size = 4`:
- `bytes = (int32)(0x40000001 * 4) = (int32)(0x100000004) = 4`
- `bytes / elem_size = 1`
- `1 == 0x40000001` → **FALSE** → overflow detected → returns `NULL`

This causes `TIFFFetchStripThing` to return 0, which causes
`TIFFReadDirectory` to `goto bad`, which causes `TIFFOpen` to fail.

### Flow in `tif_dirread.c`

At line 400, `TIFFReadDirectory` sets:
```c
td->td_nstrips = TIFFNumberOfStrips(tif);
// = ceil(td_imagelength / td_rowsperstrip)
// = 0x40000001 if ImageLength=0x40000001, RowsPerStrip=1
```

Then at lines 500–508:
```c
if (!TIFFFetchStripThing(tif, dp, td->td_nstrips, &td->td_stripoffset))
    goto bad;
```

`TIFFFetchStripThing` calls `_TIFFCheckMalloc(tif, 0x40000001, 4, ...)` which
detects the overflow and returns NULL. The input file cannot be opened.

### The symmetry problem

The `CopyField` macro in `tiffcp` (tiffsplit.c) copies `TIFFTAG_IMAGELENGTH`
and `TIFFTAG_ROWSPERSTRIP` from input to output unchanged. Therefore:
- `TIFFNumberOfStrips(output)` = `TIFFNumberOfStrips(input)` = same `nstrips`
- Any `nstrips` that would cause overflow in `TIFFSetupStrips` on the write side
  would also have caused overflow in `TIFFFetchStripThing` on the read side,
  preventing the file from being opened at all.

### Confirmed Failure

Running the PoC with `ImageLength=0x40000001, RowsPerStrip=1, StripOffsets count=2` produces:
```
vuln_001.tif: Warning, incorrect count for field "StripOffsets" (2, expecting 1073741825); tag ignored.
vuln_001.tif: Failed to allocate memory for for strip array (1073741825 elements of 4 bytes each).
```

The second message confirms `_TIFFCheckMalloc` catches the overflow during reading.
`tiffsplit` exits without copying anything; the write path is never reached.

## Conclusion

The vulnerability exists in the `tif_write.c` write path (`_TIFFmalloc` used without
overflow detection), but it is **unreachable** via `tiffsplit` with a crafted input TIFF.
The read path (`_TIFFCheckMalloc`) detects the same arithmetic overflow and rejects any
TIFF that would otherwise trigger the write-side vulnerability.

**Status: SKIPPED** — the vulnerability cannot be triggered by passing a crafted TIFF
file on the command line to `tiffsplit`.

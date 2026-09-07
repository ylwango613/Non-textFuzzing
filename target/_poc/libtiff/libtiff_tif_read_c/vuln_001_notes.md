# VULN 001 - TIFFReadRawStrip1 mmap uint32 Overflow OOB Read

## Vulnerability

- **File**: `libtiff/libtiff/tif_read.c`, lines 197-209
- **Function**: `TIFFReadRawStrip1()` (mmap branch)
- **CWE**: CWE-125 (Out-of-bounds Read)

## Root Cause

In the mmap branch of `TIFFReadRawStrip1()`, the bounds check reads:

```c
if (td->td_stripoffset[strip] + size > tif->tif_size) {
    /* error */
}
_TIFFmemcpy(buf, tif->tif_base + td->td_stripoffset[strip], size);
```

`td->td_stripoffset[strip]` is `uint32` and `tif->tif_size` is `toff_t` (also `uint32` in this
libtiff version). The addition `offset + size` is performed in 32-bit unsigned arithmetic.

When `StripOffset = 0xFFFFFF00` and `size = 256 (0x100)`:

```
0xFFFFFF00 + 0x100 = 0x100000000  (truncated to uint32)  = 0x00000000
```

The check `0 > file_size` is always FALSE, so the bounds guard is completely bypassed.
The subsequent `_TIFFmemcpy` reads from `tif_base + 0xFFFFFF00`, which is far beyond the
memory-mapped region (the file is only 162 bytes).

## PoC Approach

`vuln_001_gen.py` constructs a minimal, valid-enough strip-based TIFF (162 bytes total):

- 4x4 grayscale image, 8 bpp, no compression
- **StripOffsets[0] = 0xFFFFFF00** (near UINT32_MAX)
- **StripByteCounts[0] = 256**
- No actual strip data in the file; the offset points far outside it

The TIFF is valid enough that libtiff opens it successfully and reaches the strip-read path.

## Trigger Path

```
tiffsplit main()
  -> TIFFOpen()           -- opens and mmaps the file
  -> tiffcp()
  -> cpStrips()           -- reads strips of the input TIFF
  -> TIFFReadRawStrip()   -- calls with bytecount = 256
  -> TIFFReadRawStrip1()  -- mmap branch: overflow bypasses bounds check
  -> _TIFFmemcpy()        -- SEGV: reads from tif_base + 0xFFFFFF00
```

## Observed Crash (ASAN)

```
ERROR: AddressSanitizer: SEGV on unknown address 0x7f2ec53d8f00
Signal caused by: READ memory access
  #0 memcpy
  #1 _TIFFmemcpy
  #2 TIFFReadRawStrip1
  #3 TIFFReadRawStrip
  #4 cpStrips
  #5 tiffcp
  #6 main
```

The crash address `= mmap_base + 0xFFFFFF00` confirms the OOB read exactly as predicted.

## Files

| File | Purpose |
|---|---|
| `vuln_001_gen.py` | Generates the crafted TIFF |
| `vuln_001.tif` | The malicious TIFF (162 bytes) |
| `vuln_001_run.sh` | Runs tiffsplit and captures output/ASAN logs |
| `vuln_001_result.txt` | Raw output + ASAN log from the run |
| `vuln_001_status.txt` | VERIFIED_CRASH |

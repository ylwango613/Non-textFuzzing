# VULN 001: Integer Overflow in rastersize Leading to Heap Buffer Overflow

## Vulnerability

**File**: `libtiff/tools/thumbnail.c`  
**Function**: `generateThumbnail()`  
**Lines**: 565-568

```c
rowsize = TIFFScanlineSize(in);          // tsize_t (int32)
rastersize = sh * rowsize;               // integer overflow when result > INT32_MAX
raster = (unsigned char*)_TIFFmalloc(rastersize);  // malloc(0) -> non-NULL
// ...
TIFFReadEncodedStrip(in, s, rp, -1);    // writes into 0-byte allocation -> heap overflow
```

## Root Cause

`tsize_t` in this version of libtiff is defined as `int32` (32-bit signed integer).  
The product `sh * rowsize` overflows when:
- `bps=1`, `spp=1` (passes the `if (spp != 1 || bps != 1) return 0;` guard)
- `ImageWidth = 0x80000000` (2147483648): `rowsize = ceil(2147483648/8) = 268435456`
- `ImageLength = 16` (`sh=16`): `rastersize = 16 * 268435456 = 4294967296` → wraps to **0** in int32

`_TIFFmalloc(0)` returns a non-NULL pointer to a 0-byte (or minimal) allocation.  
`TIFFReadEncodedStrip` then writes `StripByteCounts` bytes into this allocation, causing a **heap buffer overflow**.

## PoC TIFF Structure

| Field                   | Value                      | Reason                               |
|-------------------------|----------------------------|--------------------------------------|
| ImageWidth              | 0x80000000 (2147483648)    | rowsize = 268435456                  |
| ImageLength             | 16                         | sh=16; 16*268435456 overflows int32  |
| BitsPerSample           | 1                          | Required for bps==1 check            |
| SamplesPerPixel         | 1                          | Required for spp==1 check            |
| Compression             | 1 (NONE)                   | Uncompressed; direct read            |
| RowsPerStrip            | 16                         | Single strip containing all rows     |
| StripByteCounts         | 4096                       | Bytes written into 0-byte buffer     |

## Trigger Path

```
thumbnail <input.tif> <output.tif>
  -> main()
  -> generateThumbnail(in, out)
  -> rastersize = sh * rowsize  // overflow to 0
  -> _TIFFmalloc(0)             // returns non-NULL
  -> TIFFReadEncodedStrip(in, 0, rp, -1)  // writes 4096 bytes -> heap overflow
```

## Files

- `vuln_001_gen.py`: Generates the malicious `vuln_001.tif`
- `vuln_001_run.sh`: Runs the PoC with ASAN and captures results
- `vuln_001.tif`: The generated malicious TIFF file
- `vuln_001_result.txt`: ASAN/program output after running
- `vuln_001_status.txt`: Final verdict (VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED)

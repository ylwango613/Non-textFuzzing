# VULN 001 — Heap Buffer Overflow in fpAcc() (tif_predict.c)

## Vulnerability Summary

**Function:** `fpAcc()` in `libtiff/tif_predict.c` (lines 352–383)  
**Binary:** `tiffsplit`  
**Type:** Heap buffer overflow (write-past-end)

## Root Cause

`fpAcc()` accumulates the floating-point predictor deltas across a decoded scanline buffer. The loop:

```c
tsize_t count = cc;            // cc = total bytes in strip row
while (count > stride) {
    REPEAT4(stride, cp[stride] += cp[0]; cp++)
    count -= stride;
}
```

uses `REPEAT4(stride, ...)` which always executes exactly `stride` write operations per loop body. If `cc` is **not a multiple of `stride`** (= `SamplesPerPixel` for `PLANARCONFIG_CONTIG`), the final `REPEAT4` iteration advances `cp` beyond the end of the buffer.

## Trigger Parameters

| Parameter            | Value | Reason                                    |
|----------------------|-------|-------------------------------------------|
| `BitsPerSample`      | 9     | Non-multiple-of-8; `bps = 9/8 = 1` (int) |
| `SamplesPerPixel`    | 5     | `stride = 5`                              |
| `ImageWidth`         | 3     |                                           |
| `Predictor`          | 3     | `PREDICTOR_FLOATINGPOINT` → `fpAcc()`     |
| `SampleFormat`       | 3     | `SAMPLEFORMAT_IEEEFP` (required for FP)   |
| `PlanarConfig`       | 1     | `PLANARCONFIG_CONTIG` (stride=SamplesPerPixel) |
| `Compression`        | 8     | Deflate/ZIP (predictor applied on decode) |

## Math

```
rowsize = ceil(9 * 3 * 5 / 8) = ceil(135/8) = 17 bytes  (buffer size)
stride  = 5  (SamplesPerPixel, CONTIG)
17 % 5  = 2  ≠ 0  → misalignment

Loop iterations (count starts at 17):
  iter 1: count=17>5 → REPEAT4 writes cp[5..9];  count=12, cp→10
  iter 2: count=12>5 → REPEAT4 writes cp[10..14]; count=7,  cp→10
  iter 3: count=7>5  → REPEAT4 writes cp[15..19]; count=2,  cp→15
           cp[17], cp[18], cp[19] are 3 bytes PAST the 17-byte buffer → overflow
```

## PoC Strategy

1. Build a minimal TIFF with the above parameters using Python `struct` + `zlib`.
2. The strip contains 17 zero-bytes compressed with zlib (compression=8).
3. `tiffsplit` opens the file, reads the directory, decompresses the strip, and then
   `PredictorDecodeRow` → `fpAcc()` triggers the write past the heap buffer.

## Call Path

**Important caveat on tiffsplit:** tiffsplit uses `TIFFReadRawStrip()` which
reads the raw compressed bytes from disk and writes them to the output file
without decoding. This bypasses the predictor decode path entirely — fpAcc()
is never called via tiffsplit. The TIFF is accepted by tiffsplit without error.

The vulnerability is triggered by any tool that calls `TIFFReadEncodedStrip()`
or `TIFFReadScanline()`, such as `tiffcp`:

```
tiffcp main()
  → TIFFOpen()
  → TIFFReadDirectory()
      → ZIPInit() registers ZIPSetupDecode
  → cpDecodedStrips()
      → TIFFReadEncodedStrip()
          → TIFFStartStrip()
              → ZIPSetupDecode()     [tif_zip.c]
              → PredictorSetupDecode() [tif_predict.c]
                  → PredictorSetup() sets sp->stride=5
          → ZIPPreDecode() / ZIPDecode()  → 17 bytes in heap buffer
          → PredictorDecodeTile()
              → fpAcc(tif, buffer, 17)  ← heap overflow here
```

## Confirmed ASAN Output (tiffcp)

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x503000000051
READ of size 1 at 0x503000000051
  #0 fpAcc (libtiff.so.3)
  #1 PredictorDecodeTile (libtiff.so.3)
  #2 TIFFReadEncodedStrip (libtiff.so.3)
  #3 cpDecodedStrips (tiffcp)
0x503000000051 is located 0 bytes to the right of 17-byte region
[0x503000000040,0x503000000051)
```

## Files

- `vuln_001_gen.py`     — crafts `vuln_001.tif`
- `vuln_001_run.sh`     — runs tiffsplit then tiffcp; captures ASAN output
- `vuln_001.tif`        — malicious TIFF (generated)
- `vuln_001_result.txt` — raw output / ASAN report
- `vuln_001_status.txt` — final verdict (VERIFIED_CRASH)

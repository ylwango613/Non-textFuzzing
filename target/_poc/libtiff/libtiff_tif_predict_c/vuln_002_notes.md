# VULN 002: Heap Buffer OOB Read in fpDiff() — PoC Notes

## Vulnerability Summary

- **File**: `libtiff/libtiff/tif_predict.c`, function `fpDiff()`, lines 517-548
- **Type**: Heap buffer out-of-bounds read
- **CWE**: CWE-125

## Root Cause Analysis

`fpDiff()` is the encoding-side floating-point predictor (PREDICTOR=3). It performs
a byte-reordering followed by backwards differencing:

```c
static void fpDiff(TIFF* tif, tidata_t cp0, tsize_t cc) {
    tsize_t stride = PredictorState(tif)->stride;
    uint32 bps = tif->tif_dir.td_bitspersample / 8;  // INTEGER DIVISION
    ...
    cp = (uint8 *) cp0;
    cp += cc - stride - 1;
    for (count = cc; count > stride; count -= stride)
        REPEAT4(stride, cp[stride] -= cp[0]; cp--)
}
```

When `BitsPerSample=9`: `bps = 9/8 = 1` (integer division truncates).
The loop count is based on `cc` (raw byte count), not on `cc / bps`.

For the parameters: `width=3, samplesperpixel=5, bitspersample=9`:
- `cc = rowsize = (3*5*9+7)/8 = 17 bytes`
- `stride = 5` (CONTIG mode)
- `17 % 5 = 2 != 0` → the loop does not divide evenly

### OOB Trace (cc=17, stride=5)

```
cp = cp0 + 11  (cc - stride - 1)
REPEAT4(5, cp[stride] -= cp[0]; cp--) runs 5 times per loop iteration

Iteration 1 (count=17): cp goes cp0+11 → cp0+6, all reads valid
Iteration 2 (count=12): cp goes cp0+6  → cp0+1, all reads valid
Iteration 3 (count=7):
  Step 1: reads cp0[6],  cp0[1]  -- valid
  Step 2: reads cp0[5],  cp0[0]  -- valid
  Step 3: reads cp0[4],  cp0[-1] -- OOB READ cp0[-1]
  Step 4: reads cp0[3],  cp0[-2] -- OOB READ cp0[-2]
  Step 5: reads cp0[2],  cp0[-3] -- OOB READ cp0[-3]
count = 7-5 = 2, 2 > 5 is false, loop exits.
```

## PoC Strategy

The crafted TIFF (`vuln_002.tif`) has:
- `BitsPerSample=9` (non-multiple of 8)
- `SamplesPerPixel=5` (stride=5)
- `Width=3` (gives rowsize=17, 17%5=2≠0)
- `Predictor=3` (FLOATING_POINT)
- `SampleFormat=6` (IEEEFP)
- `Compression=8` (Deflate/ZIP)
- `PlanarConfig=1` (CONTIG)
- Strip: 17 zero bytes, zlib-compressed

## Why tiffsplit Cannot Trigger fpDiff

`fpDiff` is only called in the **encoding** path:

```
TIFFWriteEncodedStrip() -> tif_codec->tif_encoderow() (e.g., ZIP)
  -> sp->encoderow (= PredictorEncodeRow) -> sp->encodepfunc (= fpDiff)
```

However, `tiffsplit`'s `cpStrips()` function copies strips using:

```c
TIFFReadRawStrip(in, s, buf, bytecounts[s])
TIFFWriteRawStrip(out, s, buf, bytecounts[s])
```

`TIFFWriteRawStrip` writes compressed data **directly** to the output file,
bypassing `PredictorEncodeRow` and thus `fpDiff` entirely. The predictor
fields (tag 317) are copied to the output IFD as metadata, but the encoding
function chain is never invoked during the strip data write.

## Verdict

**SKIPPED**: `fpDiff` is unreachable through `tiffsplit`'s raw strip copy path.
The vulnerability exists in the libtiff library code but cannot be triggered
by `tiffsplit` alone. It would be triggerable by any application that calls
`TIFFWriteEncodedStrip()` (or `TIFFWriteScanline()`) with the malicious TIFF
parameters described above.

## Variations Attempted

The issue is not with the specific parameter values but with the fundamental
design of tiffsplit: it always uses raw strip copy (`TIFFReadRawStrip` /
`TIFFWriteRawStrip`). No variation of input parameters would cause tiffsplit
to call `fpDiff`.

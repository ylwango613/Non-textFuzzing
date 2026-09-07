# VULN 002: LogL16Decode() Out-of-Bounds Read

## Vulnerability Details

- **ID**: VULN 002
- **Function**: `LogL16Decode()`
- **File**: `libtiff/libtiff/tif_luv.c`, lines 210-214
- **Compression**: `COMPRESSION_SGILOG` = 34676 (0x8774)
- **Photometric**: `PHOTOMETRIC_LOGL` = 32844 (0x806C)
- **CWE**: CWE-125 (Out-of-Bounds Read)

## Vulnerable Code

```c
// tif_luv.c lines 209-221
for (shft = 2*8; (shft -= 8) >= 0; ) {
    for (i = 0; i < npixels && cc > 0; )
        if (*bp >= 128) {        // run branch: entered when byte >= 0x80
            rc = *bp++ + (2-128);
            b = (int16)(*bp++ << shft);  // <-- OOB READ HERE
            cc -= 2;
            while (rc-- && i < npixels)
                tp[i++] |= b;
        } else {                 // non-run branch
            ...
        }
```

## Trigger Condition

When `StripByteCounts = 1` (cc = 1):
1. The loop condition `cc > 0` is satisfied (cc=1).
2. The first byte `*bp = 0x80` (>= 128) enters the **run branch**.
3. `bp++` advances past the first byte (cc should be 0 now, but cc -= 2 happens later).
4. `*bp++` reads the **second byte**, which is past the end of the 1-byte strip buffer — **out-of-bounds read**.
5. `cc -= 2` sets cc to -1, which exits the outer loop.

## TIFF Construction

| Field | Value | Notes |
|-------|-------|-------|
| ImageWidth | 1 | Minimal image |
| ImageLength | 1 | Single row |
| BitsPerSample | 16 | Required for LogL16 |
| Compression | 34676 | SGILOG selects LogL16Decode |
| PhotometricInterpretation | 32844 | LOGL routes to LogL16Decode |
| SamplesPerPixel | 1 | Grayscale |
| RowsPerStrip | 1 | One row per strip |
| StripByteCounts | **1** | Only 1 byte: triggers boundary condition |
| StripData | `0x80` | >= 128: enters run branch |

## Files

- `vuln_002_gen.py` - Python script to generate the PoC TIFF file
- `vuln_002_run.sh` - Shell script to run tiffsplit on the PoC TIFF
- `vuln_002.tif` - Generated PoC TIFF file (created by gen script)
- `vuln_002_result.txt` - Runtime output including ASAN/UBSAN findings
- `vuln_002_status.txt` - Final verdict (VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED)

## Expected Behavior

With AddressSanitizer-instrumented `tiffsplit`, this should trigger a
`heap-buffer-overflow` or `stack-buffer-overflow` error on the second `bp++`
dereference inside `LogL16Decode()`.

# VULN 003: LogLuvDecode32 Out-of-Bounds Read

## Summary
An out-of-bounds read occurs in `LogLuvDecode32()` in `libtiff/libtiff/tif_luv.c` at line 313.

## Location
- **File**: `libtiff/libtiff/tif_luv.c`
- **Function**: `LogLuvDecode32()`
- **Lines**: 310–314

## Vulnerable Code
```c
for (i = 0; i < npixels && cc > 0; )
    if (*bp >= 128) {       /* run */
        rc = *bp++ + (2-128);
        b = (uint32)*bp++ << shft;  // LINE 313: reads 2nd byte without checking cc
        cc -= 2;
```

## Trigger Condition
- Loop guard only checks `cc > 0` (cc=1 is sufficient to enter)
- When `*bp >= 0x80`, the **run branch** is taken
- Line 312 consumes `bp[0]` (valid, cc was 1)
- Line 313 reads `bp[1]` unconditionally — **this is one byte past the strip buffer** (OOB read)
- `cc -= 2` then makes cc = -1

## TIFF Configuration
| Field | Value | Reason |
|-------|-------|--------|
| Compression | 34676 (SGILOG) | Routes to LogLuvDecode32 |
| PhotometricInterpretation | 32845 (LOGLUV) | Required for LOGLUV color path |
| SamplesPerPixel | 3 | Color image |
| BitsPerSample | 8 | |
| ImageWidth | 1 | Minimal image |
| ImageLength | 1 | Minimal image |
| RowsPerStrip | 1 | |
| StripByteCounts | **1** | Only 1 byte in strip => cc=1 |
| strip_data[0] | **0x80** | >= 128, enters run branch |

## vs VULN 002
- VULN 002 targets `LogLuvDecode24()` (LOGL, grayscale) with Compression=SGILOG24
- VULN 003 targets `LogLuvDecode32()` (LOGLUV, color) with Compression=SGILOG

## Files
- `vuln_003_gen.py` — generates `vuln_003.tif`
- `vuln_003_run.sh`  — runs tiffsplit and collects ASAN/UBSAN output
- `vuln_003.tif`     — crafted TIFF triggering the OOB read
- `vuln_003_result.txt` — runtime output
- `vuln_003_status.txt` — final verdict

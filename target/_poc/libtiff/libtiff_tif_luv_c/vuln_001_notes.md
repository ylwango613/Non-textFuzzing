# VULN 001 — LogLuvDecode24 Out-of-Bounds Read

## Location
- **File**: `libtiff/libtiff/tif_luv.c`
- **Function**: `LogLuvDecode24()`
- **Lines**: 262–266

## Vulnerable Code
```c
bp = (unsigned char*) tif->tif_rawcp;
cc = tif->tif_rawcc;                      // equals StripByteCounts at strip start
for (i = 0; i < npixels && cc > 0; i++) {
    tp[i] = bp[0] << 16 | bp[1] << 8 | bp[2];  // always reads 3 bytes
    bp += 3;
    cc -= 3;
}
```

## Root Cause
The loop guard `cc > 0` only checks that at least **one** byte remains, but the
loop body unconditionally reads **three** bytes (`bp[0]`, `bp[1]`, `bp[2]`).

- If `cc == 2`: `bp[2]` is a 1-byte out-of-bounds read.
- If `cc == 1`: `bp[1]` and `bp[2]` are both out-of-bounds reads.

`cc` is initialized from `tif->tif_rawcc`, which is set to the strip's
`StripByteCounts` value when the strip is loaded.

## Trigger Conditions
| Tag                         | Value                      |
|-----------------------------|----------------------------|
| Compression                 | 34677 (SGILOG24, 0x8775)   |
| PhotometricInterpretation   | 32845 (LOGLUV, 0x806D)     |
| SamplesPerPixel             | 3                          |
| BitsPerSample               | 8                          |
| ImageWidth                  | 1                          |
| ImageLength                 | 1                          |
| RowsPerStrip                | 1                          |
| StripByteCounts             | **2** (or 1)               |

## PoC Files
| File               | Purpose                                      |
|--------------------|----------------------------------------------|
| `vuln_001_gen.py`  | Generates `vuln_001.tif`                     |
| `vuln_001_run.sh`  | Runs `tiffsplit` under ASAN and captures log |
| `vuln_001.tif`     | Malformed TIFF (generated at runtime)        |
| `vuln_001_result.txt` | Raw output and ASAN report              |
| `vuln_001_status.txt` | Final verdict                           |

## Expected Outcome
AddressSanitizer should report a **heap-buffer-overflow** (READ of size 1) at the
`bp[2]` access when `StripByteCounts=2`.

## CWE / Severity
- **CWE-125**: Out-of-Bounds Read
- **Impact**: Information disclosure; potential denial of service via crafted TIFF.

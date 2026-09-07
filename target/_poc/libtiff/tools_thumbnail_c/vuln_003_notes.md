# VULN 003: Use of Uninitialized Pointer `bytecounts` in `cpStrips`

## File
`libtiff/tools/thumbnail.c`, function `cpStrips()`, lines 269–273

## Root Cause
`tsize_t *bytecounts` is declared on the stack without initialization. The code calls:
```c
TIFFGetField(in, TIFFTAG_STRIPBYTECOUNTS, &bytecounts);
```
but does **not** check the return value. When the `STRIPBYTECOUNTS` tag (0x0117) is
absent from the input TIFF, `TIFFGetField` returns 0 and leaves `bytecounts` holding
a garbage stack value. The subsequent loop at line 273 (`bytecounts[s]`) then
dereferences this uninitialized pointer, causing a segfault or heap/stack corruption
detectable by ASAN.

## Trigger Path
```
main() → cpIFD() [line 116] → cpStrips() [line 337] → bytecounts[s] [line 273]
```

## Required Conditions
- Strip-based TIFF (`TIFFIsTiled` returns false)
- `STRIPBYTECOUNTS` tag **omitted** from IFD

## PoC Files
| File | Purpose |
|------|---------|
| `vuln_003_gen.py` | Constructs `vuln_003.tif` — a 32×32 grayscale strip TIFF without tag 0x0117 |
| `vuln_003_run.sh` | Runs `thumbnail` under ASAN and collects output |
| `vuln_003.tif`    | Generated malicious TIFF (auto-created by gen script) |
| `vuln_003_result.txt` | Captured stdout/stderr + ASAN log excerpts |

## Usage
```bash
bash vuln_003_run.sh
cat vuln_003_result.txt
```

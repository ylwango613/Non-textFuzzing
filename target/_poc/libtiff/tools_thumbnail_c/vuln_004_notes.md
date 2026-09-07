# VULN 004: Use of Uninitialized Pointer bytecounts in cpTiles

## Summary
In `libtiff/tools/thumbnail.c`, function `cpTiles()` (lines 303-307), the local variable
`tsize_t *bytecounts` is declared uninitialized on the stack. The return value of
`TIFFGetField(in, TIFFTAG_TILEBYTECOUNTS, &bytecounts)` is not checked. When the
TILEBYTECOUNTS tag is absent from the TIFF file, `bytecounts` retains a garbage stack
value. A subsequent `bytecounts[t]` dereference uses this invalid pointer.

## Trigger Conditions
- Input must be a tiled TIFF: `TIFFIsTiled()` returns true (requires TileWidth=0x0142 and TileLength=0x0143 tags)
- TILEBYTECOUNTS tag (0x0145) must be **absent** from the IFD

## Call Chain
`thumbnail main()` → `cpIFD()` (line 116) → `cpTiles()` (line 334) → `bytecounts[t]` deref

## PoC File
- `vuln_004_gen.py`: Generates a tiled TIFF without the TILEBYTECOUNTS tag
- `vuln_004.tif`: The crafted input file
- `vuln_004_run.sh`: Runs `thumbnail` with ASAN logging enabled

## Expected Result
ASAN or UBSAN should report an invalid memory access (use of uninitialized pointer /
heap-use-after-free or wild dereference) when `bytecounts[t]` is accessed.

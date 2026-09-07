# VULN-001 PoC Notes: uint16 Wrap-around OOB Heap Write in TIFFCheckDirOffset

## Vulnerability Summary

`TIFFCheckDirOffset` in `tif_dirread.c` (lines 1082-1102) uses a `uint16` counter
`tif->tif_dirnumber`. After 65535 increments, incrementing once more wraps it to 0.
Line 1102 then executes `tif->tif_dirlist[0 - 1]` (where 0 is uint16, promoted to int -1),
writing 4 bytes before the heap buffer — an OOB heap write.

## PoC Approach

The PoC generates a 393,224-byte TIFF file containing a chain of 65,536 minimal IFDs
(8-byte header + 65536 × 6-byte IFDs). Each IFD has `entry_count=0` and a `next_ifd_offset`
pointing to the next IFD in sequence, with the last IFD pointing to offset 0 (end of chain).

`tiffsplit` was used as the trigger, which iterates through IFDs via a do-while loop:
`TIFFOpen → TIFFReadDirectory (×N) → TIFFCheckDirOffset (×N)`.

## Why the Crash Did Not Occur

The 0-entry IFD format caused an early failure in the call chain:

1. `TIFFOpen` calls `TIFFReadDirectory`, which calls `TIFFCheckDirOffset` (call #1).
2. `TIFFReadDirectory` then calls `TIFFFetchDirectory` to read the IFD entries.
3. Inside `TIFFFetchDirectory` (line 1165), `_TIFFCheckMalloc(tif, 0, sizeof(TIFFDirEntry), ...)`
   is called because `dircount = 0`. In `_TIFFCheckRealloc` (tif_aux.c line 46), the condition
   `if (nmemb && ...)` is false when `nmemb = 0`, so `cp = NULL` is returned.
4. `TIFFFetchDirectory` returns 0 (failure).
5. `TIFFReadDirectory` returns 0 with error "Failed to read directory at offset 0".
6. `TIFFOpen` returns NULL (since `TIFFReadDirectory` failed).
7. The do-while loop in `tiffsplit` never executes.

Total `TIFFCheckDirOffset` calls: **1** (far less than 65536 needed for wrap-around).

## Additional Limitation: tiffsplit MAXFILES

Even if IFDs had ≥1 entry (bypassing the malloc issue), `tiffsplit` has a hard
`MAXFILES = 17576` limit (tools/tiffsplit.c line 118). With the default prefix,
the tool exits after ~52,728 output files — still less than 65,536.

## What Would Be Required to Trigger the Bug

To reliably trigger the OOB write:
- Each IFD must have at least 1 directory entry to pass `_TIFFCheckMalloc`.
- `tiffcp` must succeed for each IFD processed (requires STRIPBYTECOUNTS, STRIPOFFSETS, etc.).
- The MAXFILES limit (52,728 with default prefix) prevents reaching 65,536 IFDs with tiffsplit.
- A tool without an output-file count limit (e.g., `tiffinfo`) would be a more suitable trigger.

## Files

- `vuln_001_gen.py`: Generates `vuln_001.tif` (393,224 bytes, 65,536 zero-entry IFDs)
- `vuln_001_run.sh`: Runs `tiffsplit` against `vuln_001.tif` with ASAN logging
- `vuln_001_result.txt`: Output from the run (tiffsplit error, no ASAN events)
- `vuln_001_status.txt`: UNVERIFIED

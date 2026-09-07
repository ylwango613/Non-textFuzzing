# VULN 001 – OOB Read via `.front()` on Empty GPS Reference String

## Vulnerability

**Function**: `Converter::cnvExifGPSCoord()` in `src/convert.cpp`  
**Line**: 836  
**CWE**: CWE-125 (Out-of-Bounds Read)

## Root Cause

At line 836 of `convert.cpp`:

```cpp
(*xmpData_)[to] = stringFormat("{},{:.7f}{}", ideg, min, refPos->toString().front());
```

The code finds the GPS reference tag (e.g. `GPSLatitudeRef`) using `findKey()` and only
checks `refPos != exifData_->end()` (line 815). It never checks that the datum's string
representation is non-empty before calling `.front()`.

If the GPS reference tag (e.g. `GPSLatitudeRef`, tag 0x0001) is stored as ASCII type
with `count=0` (zero-length value field), `refPos->toString()` returns an empty `std::string`,
and calling `.front()` on it is undefined behaviour — typically a heap or stack buffer
overread, detected by ASAN as a heap-buffer-overflow.

## Trigger Conditions

1. A TIFF (or JPEG/EXIF) file contains a GPS IFD.
2. The GPS IFD has a valid `GPSLatitude` (tag 0x0002) with exactly 3 RATIONAL values
   (count=3), so the `pos->count() != 3` guard passes.
3. The corresponding `GPSLatitudeRef` (tag 0x0001) exists (so `refPos != end()` passes)
   but is ASCII type with `count=0` (empty string).
4. The code reaches line 836 and calls `.front()` on the empty string.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001_input.tiff` and `vuln_001_input.jpg` |
| `vuln_001_run.sh` | Runs exiv2 against both files with ASAN logging |
| `vuln_001_result.txt` | Output captured from the run |
| `vuln_001_status.txt` | One-line status: VERIFIED_CRASH / VERIFIED_BEHAVIOR / UNVERIFIED / ERROR |

## Trigger Command

```bash
exiv2 pr vuln_001_input.tiff
```

The `pr` command triggers XMP printing which invokes `copyExifToXmp()` →
`cnvExifGPSCoord()` → `.front()` UB.

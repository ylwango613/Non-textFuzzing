# VULN 001 — OOB Read in AP4_AvccAtom::Create()

## File
`Bento4/Source/C++/Core/Ap4AvccAtom.cpp`, line 75

## Vulnerability Summary
When an `avcC` atom has `size=8` (header only, no payload), `payload_size` is computed as `8 - 8 = 0`. A zero-byte `AP4_DataBuffer` is allocated, but `payload[0]` is read at line 75 **before** the size guard at line 80 (`if (payload_size < 6) return NULL`). This results in a 1-byte heap-buffer-overflow read past a 0-byte allocation.

## PoC Strategy
The crafted MP4 (`vuln_001.mp4`) embeds an `avcC` box with `size=8` (empty payload) in the required nesting path:

```
moov > trak > mdia > minf > stbl > stsd > avc1 > avcC
```

All surrounding boxes are valid enough to allow Bento4's atom factory to navigate down to the `avcC` box and invoke `AP4_AvccAtom::Create()`. When `Create()` reads `payload[0]` on a zero-byte buffer, ASAN detects a heap-buffer-overflow read.

## Expected Output
With an ASAN-instrumented binary, running:
```
mp42aac vuln_001.mp4 /dev/null
```
should produce an ASAN report containing:
```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1
... AP4_AvccAtom::Create ...
```

## Files
- `vuln_001_gen.py` — generates `vuln_001.mp4`
- `vuln_001_run.sh` — runs the binary under ASAN and captures output
- `vuln_001_result.txt` — combined stdout/stderr + ASAN log (generated at runtime)
- `vuln_001_status.txt` — single-word crash status

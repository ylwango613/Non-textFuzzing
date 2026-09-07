# VULN 001 – AP4_CttsAtom Missing entry_count Bounds Check

## Vulnerability Summary

**Target binary**: `mp42aac` (Bento4)  
**Affected component**: `AP4_CttsAtom` constructor (`Source/C++/Core/Ap4CttsAtom.cpp`)  
**Class**: Denial of Service — unbounded memory allocation (std::bad_alloc)  
**Box path**: `moov → trak → mdia → minf → stbl → ctts`

## Root Cause

When Bento4 parses a `ctts` (Composition Time to Sample) box, the
`AP4_CttsAtom` constructor reads a 32-bit `entry_count` from the stream and
immediately calls `AP4_Array::EnsureCapacity(entry_count)` without verifying:

1. That `entry_count` is consistent with the remaining box size, or  
2. That the requested allocation is within reasonable limits.

Passing `entry_count = 0xFFFFFFFF` (4,294,967,295) causes the array to attempt
allocating approximately:

```
0xFFFFFFFF * sizeof(AP4_CttsTableEntry) ≈ 0xFFFFFFFF * 8 bytes ≈ 32 GB
```

On a 64-bit system where that amount of virtual memory is unavailable, the
`new` operator throws `std::bad_alloc`, crashing the process.

## PoC Approach

### File Structure

The crafted MP4 is minimal but structurally valid enough for `mp42aac` to
descend into the `stbl` box and attempt to parse `ctts`:

```
ftyp  (brand: isom)
moov
  mvhd  (timescale=1000, duration=0)
  trak
    tkhd  (track_id=1, flags=3)
    mdia
      mdhd  (timescale=44100)
      hdlr  (handler='soun')
      minf
        smhd
        dinf
          dref (url, self-contained)
        stbl
          stsd  (1 × mp4a entry with minimal esds)
          stts  (1 entry: count=1, delta=1024)
          stsc  (1 entry)
          stsz  (1 sample, size=4)
          stco  (1 chunk)
          ctts  ← MALICIOUS
```

### Malicious ctts box layout

| Offset | Field         | Value                |
|--------|---------------|----------------------|
| 0–3    | size          | `0x00000014` (20)    |
| 4–7    | type          | `ctts`               |
| 8–11   | version/flags | `0x00000000`         |
| 12–15  | entry_count   | `0xFFFFFFFF`         |
| 16+    | entries       | (none — box ends)    |

The declared `entry_count` is 4,294,967,295 but the box contains zero entries.
Bento4 trusts the field and tries to pre-allocate capacity for all of them.

### Generator

`vuln_001_gen.py` builds the MP4 bottom-up using only `struct.pack` (no
third-party libraries). All sizes are calculated after assembling child boxes so
parent `size` fields are accurate.

### Runner

`vuln_001_run.sh` invokes `mp42aac` with `ASAN_OPTIONS` so that if the binary
was compiled with AddressSanitizer the log is captured. Even without ASAN the
`std::bad_alloc` exception propagates out unhandled, causing an abnormal
termination that the script records in `vuln_001_result.txt`.

## Expected Outcome

```
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
Aborted (core dumped)
```

or, with ASAN + libstdc++ instrumentation:

```
==PID==ERROR: AddressSanitizer: out-of-memory …
```

## Remediation

Before calling `EnsureCapacity`, `AP4_CttsAtom` should validate that
`entry_count` does not exceed `(remaining_bytes / sizeof(AP4_CttsTableEntry))`:

```cpp
AP4_UI32 remaining = size - AP4_FULL_ATOM_HEADER_SIZE - 4;
if (entry_count > remaining / 8) {
    return AP4_ERROR_INVALID_FORMAT;
}
```

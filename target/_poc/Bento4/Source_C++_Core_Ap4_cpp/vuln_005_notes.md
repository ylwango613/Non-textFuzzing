# VULN 005 - AP4_TrunAtom Unchecked sample_count

## Vulnerability Summary

**Location**: `Ap4TrunAtom.cpp:127`  
**Function**: `AP4_TrunAtom::AP4_TrunAtom()`  
**Type**: Denial of Service (DoS) via unbounded memory allocation

## Root Cause

In the constructor for `AP4_TrunAtom`, the `sample_count` field is read directly from the file-controlled trun box payload and passed to `m_Entries.SetItemCount(sample_count)` without any bounds check against the actual box size. When `sample_count = 0x10000000`, this triggers an allocation of approximately `0x10000000 * sizeof(Entry)` bytes (~1-4 GB), resulting in `std::bad_alloc`.

## PoC Approach

1. `vuln_005_gen.py` constructs a minimal but structurally valid MP4 fragment file:
   - `ftyp` box with brand `iso5`
   - `moov` box with `mvhd`, `mvex` (containing `trex`), and `trak` (containing minimal audio track boxes)
   - `moof` box containing `mfhd` + `traf` (containing `tfhd` + malicious `trun`)
   - Empty `mdat` box

2. The malicious `trun` box uses `flags=0x000000` (no optional per-run or per-sample fields) and `sample_count=0x10000000`. This makes the box structurally valid at 16 bytes, but Bento4 will attempt to allocate a huge array for 268,435,456 entries.

## Expected Behavior

- `mp42aac` parses the MP4 file and enters `AP4_TrunAtom::AP4_TrunAtom()`
- `m_Entries.SetItemCount(0x10000000)` triggers a system memory allocation request for ~1-4 GB
- On most systems, this will result in `std::bad_alloc`, causing an uncaught exception
- The process terminates with `terminate called after throwing an instance of 'std::bad_alloc'` and `Aborted` (exit code != 0)
- This constitutes a crash/DoS condition

## Attack Vector

Any attacker who can supply a crafted MP4 file to a service using Bento4 for media processing can trigger this crash, causing denial of service.

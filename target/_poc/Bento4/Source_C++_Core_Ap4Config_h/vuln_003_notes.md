# VULN 003 — AP4_TrunAtom Unchecked SetItemCount Failure

## Vulnerability Summary

**Binary**: `mp42aac` (Bento4)  
**Location**: `Ap4TrunAtom.cpp`, lines 127-151  
**Class**: Null Pointer Dereference / Denial of Service  
**Trigger**: MP4 file with a `moof → traf → trun` box chain where `sample_count` is set to `0x10000000` (268,435,456).

## Root Cause

In `AP4_TrunAtom::AP4_TrunAtom(...)` (the parsing constructor), the code reads `sample_count` directly from the input stream as an `AP4_UI32`, then calls `m_Entries.SetItemCount(sample_count)` to preallocate that many sample-entry slots.

The return value of `SetItemCount` is **not checked**. If the internal `operator new` fails due to an excessively large allocation (e.g., 268 million entries × entry struct size overflows or exhausts memory), one of two outcomes occurs:

1. **`std::bad_alloc` thrown** — unhandled exception causes process termination (DoS).
2. **Allocation returns NULL / partial** — subsequent code iterates over `sample_count` entries via a NULL or dangling pointer, causing a **null pointer dereference** (crash).

Either outcome constitutes a Denial of Service exploitable by any untrusted MP4 file.

## MP4 Structure Used

```
ftyp (28 bytes)  — brand=isom
moov (116 bytes) — minimal, mvhd only
moof (68 bytes)
  mfhd (16 bytes) — sequence_number=1
  traf (44 bytes)
    tfhd (16 bytes) — track_id=1, flags=0x000000
    trun (20 bytes) — version=0, flags=0x000001 (data_offset present)
                      sample_count=0x10000000  ← malicious value
                      data_offset=0
                      (no actual sample entries follow)
mdat (8 bytes)   — empty
```

The `trun` box deliberately omits the actual sample entries: the parser reads `sample_count` and tries to allocate storage for 268 million entries before looping, so the allocation attempt itself is the trigger.

## Expected Behavior

- **Without ASAN**: Process crashes with SIGSEGV or terminates with `std::bad_alloc` / `std::terminate`.
- **With ASAN**: AddressSanitizer may report a heap allocation failure, a null-dereference, or the process exits with a non-zero status from the unhandled exception.

## Files

| File | Purpose |
|------|---------|
| `vuln_003_gen.py` | Generates `vuln_003.mp4` using only Python `struct`/`bytes` |
| `vuln_003_run.sh` | Runs the generator, executes `mp42aac`, collects ASAN logs |
| `vuln_003.mp4` | The malicious MP4 (generated at runtime) |
| `vuln_003_result.txt` | stdout/stderr and ASAN log excerpts from the run |
| `asan_003.log.*` | Raw ASAN output files |

## Remediation

Check the return value of `m_Entries.SetItemCount(sample_count)` and return an error (e.g., `AP4_ERROR_OUT_OF_MEMORY` or `AP4_ERROR_INVALID_FORMAT`) if it fails. Additionally, impose a reasonable upper bound on `sample_count` before attempting allocation.

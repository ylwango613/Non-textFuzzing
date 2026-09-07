# VULN 001 — ctts entry_count unbounded heap overflow / DoS

## Vulnerability Summary

- **Target binary**: `mp42aac` (Bento4, ASAN+UBSAN build)
- **Affected function**: `AP4_CttsAtom::AP4_CttsAtom()` (lines 77–98)
- **CVE class**: Heap overflow / Denial of Service (std::bad_alloc or OOB read)

## Root Cause

`AP4_CttsAtom` reads `entry_count` from the MP4 stream and immediately calls
`m_Entries.SetItemCount(entry_count)` with no upper-bound validation.

On 64-bit systems:
- `entry_count = 0x20000001` causes `operator new(0x20000001 * 8)` ≈ 4 GB allocation.
- This triggers `std::bad_alloc` (out-of-memory crash / DoS).
- On 32-bit or with certain allocator tricks, `entry_count * 8` wraps (integer overflow),
  yielding a small allocation followed by a heap OOB read when the constructor tries to
  iterate over entries that are not actually in the file.

## PoC Approach

A minimal but structurally valid MP4 file is constructed in `vuln_001_gen.py` using only
Python's `struct` module (no external dependencies):

```
ftyp
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr
      minf
        smhd
        dinf (dref with self-contained url)
        stbl
          stsd (mp4a placeholder)
          stts (1 entry)
          ctts  <-- MALICIOUS: entry_count=0x20000001, box only 16 bytes (no entries)
          stsz
          stco
```

The ctts box is only 16 bytes (4 size + 4 type + 1 version + 3 flags + 4 entry_count),
declaring `entry_count = 0x20000001` but providing zero actual entry bytes. The parser
trusts the declared count and attempts a ~4 GB allocation.

## Expected Behavior

- **ASAN build**: `std::bad_alloc` terminates the process, possibly with an ASAN
  `ERROR: AddressSanitizer: allocator is out of memory` message, or a plain `terminate()`
  crash visible in stderr / the ASAN log.
- **Release build**: `std::bad_alloc` uncaught → `std::terminate` → SIGABRT.
- In some environments with overcommit enabled, the allocation may succeed but the
  subsequent read loop causes a heap OOB read, which ASAN would report as
  `heap-buffer-overflow`.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.mp4` with malicious ctts |
| `vuln_001.mp4` | The crafted input file |
| `vuln_001_run.sh` | Runs the binary and captures ASAN output |
| `vuln_001_result.txt` | Combined stdout/stderr + ASAN log |
| `asan_001.log.*` | Raw ASAN output files |
| `vuln_001_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED |

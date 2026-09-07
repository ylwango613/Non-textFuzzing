# VULN 002 – AP4_SbgpAtom Integer Overflow PoC Notes

## Vulnerability Summary

**Function**: `AP4_SbgpAtom::AP4_SbgpAtom()` in Bento4  
**Class of bug**: Integer overflow in bounds-check expression → heap OOB / bad_alloc  

## Root Cause

In `AP4_SbgpAtom::AP4_SbgpAtom()`, the parser reads `entry_count` from the stream and
performs a bounds check of the form:

```cpp
if (remains < entry_count * 8) { /* error path */ }
```

When `entry_count = 0x20000000`, the multiplication `entry_count * 8` is computed as a
32-bit unsigned integer:

```
0x20000000 * 8 = 0x100000000  →  wraps to 0x00000000  (32-bit overflow)
```

The check becomes `remains < 0`, which is always false (unsigned comparison), so the
guard is bypassed. The code then calls `SetItemCount(0x20000000)`, attempting to
allocate approximately `0x20000000 * sizeof(Entry)` bytes (≈ 1 GB), resulting in
`std::bad_alloc` or, under ASAN, a heap allocation failure crash.

## Trigger Path

```
mp42aac input.mp4
  → AP4_AtomFactory::CreateAtomFromStream()
    → AP4_SbgpAtom::Create(size, stream)
      → new AP4_SbgpAtom(size, version, flags, stream)
```

The vulnerable atom lives at: `moov/trak/mdia/minf/stbl/sbgp`

## PoC Construction

- `vuln_002_gen.py` — builds a minimal MP4 containing the malformed `sbgp` box with
  `entry_count = 0x20000000` and only 1 real entry (8 bytes) in the payload.
- `vuln_002_run.sh` — invokes the generator then runs `mp42aac` under ASAN, capturing
  all output and ASAN logs.

## Expected Results

| Build type | Expected behaviour |
|---|---|
| ASAN (64-bit) | `std::bad_alloc` / ASAN heap-allocation-failure crash |
| UBSAN | Integer overflow reported at the multiplication site |
| Release (no sanitisers) | Likely `std::bad_alloc` termination or silent OOM |

## Files

| File | Purpose |
|---|---|
| `vuln_002_gen.py` | Generates `vuln_002.mp4` |
| `vuln_002_run.sh` | Runs the PoC and collects output |
| `vuln_002.mp4` | Generated PoC input (created at runtime) |
| `vuln_002_result.txt` | Captured stdout/stderr + ASAN log |
| `vuln_002_status.txt` | One-line verdict: VERIFIED_CRASH / UNVERIFIED / ERROR |
| `asan.log.*` | Raw ASAN report (if ASAN build) |

# VULN 003 — AP4_TrunAtom Missing sample_count Bounds Check Before Heap Allocation

## Summary

A missing bounds check in `AP4_TrunAtom` allows a crafted MP4 file to trigger a
massive heap allocation (up to ~64 GB), causing a crash or out-of-memory DoS.

## Vulnerability Location

- **File**: `Ap4TrunAtom.cpp`, line 127
- **Function**: `AP4_TrunAtom::AP4_TrunAtom(...)` constructor (called from `AP4_TrunAtom::Create`)
- **Sink**: `m_Entries.SetItemCount(sample_count)`

## Root Cause

`sample_count` is read directly from the bitstream as a 4-byte big-endian integer
(range 0–0xFFFFFFFF). It is passed without any sanity check to `SetItemCount`,
which calls `EnsureCapacity` to allocate `sample_count * sizeof(Entry)` bytes.
`sizeof(Entry)` is 16 (four `AP4_UI32` fields). For `sample_count = 0xFFFFFFFF`,
this amounts to approximately 64 GB of requested heap memory.

## Trigger Path

```
mp42aac
  → AP4_AtomFactory::CreateAtomFromStream()
  → AP4_TrunAtom::Create()
  → new AP4_TrunAtom(size, version, flags, stream)
  → m_Entries.SetItemCount(sample_count)   ← no bounds check
  → EnsureCapacity(sample_count)
  → allocate sample_count * 16 bytes       ← DoS / bad_alloc
```

## Impact

- **Denial of Service**: The process crashes (bad_alloc or NULL dereference) when
  the system cannot satisfy the allocation.
- Any application that passes user-supplied MP4 data to Bento4 is affected.
- The trun atom is inside a `moof > traf > trun` hierarchy, reachable during normal
  fragment parsing.

## Proof of Concept

The PoC crafts a minimal but structurally valid-looking MP4:

```
ftyp (20 bytes)   — brand 'isom'
moov (112 bytes)  — contains mvhd
moof              — Movie Fragment box
  mfhd (16 bytes) — sequence_number = 1
  traf            — Track Fragment box
    tfhd (16 bytes) — track_id = 1
    trun (16 bytes) — sample_count = 0xFFFFFFFF, flags = 0x000000
mdat (8 bytes)    — empty media data
```

The trun box is only 16 bytes (no optional fields due to flags=0), but it claims
`sample_count = 0xFFFFFFFF`, causing the parser to attempt a ~64 GB allocation.

## Files

| File | Description |
|------|-------------|
| `vuln_003_gen.py` | Python script generating `vuln_003.mp4` |
| `vuln_003.mp4` | Crafted MP4 triggering the vulnerability |
| `vuln_003_run.sh` | Runner script (generates MP4 then invokes mp42aac) |
| `vuln_003_result.txt` | Output of the run (stdout + stderr + ASAN log) |
| `vuln_003_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR |

## Suggested Fix

Before calling `m_Entries.SetItemCount(sample_count)`, validate that the required
data fits within the declared atom size:

```cpp
// Compute maximum plausible sample_count from atom size
AP4_UI32 max_samples = (size - header_size) / bytes_per_entry_based_on_flags;
if (sample_count > max_samples) {
    return AP4_ERROR_INVALID_FORMAT;
}
```

Alternatively, impose a hard upper bound (e.g., 1 << 20 samples) and return an
error for values exceeding it.

# VULN 004 — AP4_TfraAtom missing entry_count bounds check before heap allocation

## Vulnerability Location

**File**: `Bento4/Source/C++/Core/Ap4TfraAtom.cpp`  
**Lines**: 86–88

```cpp
AP4_UI32 entry_count = 0;
stream.ReadUI32(entry_count);
m_Entries.SetItemCount(entry_count);   // ← no validation against atom size
```

## Root Cause

After reading `entry_count` from the raw byte stream, the value is passed directly
to `AP4_Array::SetItemCount()` without any check that:

1. The reported count is plausible given the remaining atom payload length, or
2. The resulting allocation does not exceed available memory.

Each `AP4_TfraAtom::Entry` stores two 64-bit integers (time + moof_offset) plus
three variable-width counters — approximately 24 bytes minimum per entry.
Setting `entry_count = 0x08000000` (~134 million) requests ≈ 3 GiB of heap,
which either triggers `std::bad_alloc` (if ASAN/sanitizers catch it) or causes
an OOM kill in production.

## Trigger Path

```
mp42aac
  └─ AP4_File::AP4_File(stream)
       └─ AP4_AtomFactory::CreateAtomFromStream()
            └─ AP4_TfraAtom::Create(size, stream)
                 └─ new AP4_TfraAtom(size, version, flags, stream)
                       ← m_Entries.SetItemCount(0x08000000)  CRASH
```

## MP4 Structure Used in PoC

```
ftyp  (20 bytes)   — brand 'isom'
moov  (minimal)    — contains only mvhd
mdat  (8 bytes)    — empty media data
mfra               — Movie Fragment Random Access box
  tfra (28 bytes)  — version=0, flags=0, track_id=1,
                     lengths_byte=0, entry_count=0x08000000
  mfro (16 bytes)  — back-pointer to mfra size
```

The tfra atom body is only 28 bytes (no actual entries) — the crash occurs
during the `SetItemCount` allocation, before any entry data is read.

## Expected Behavior vs. Actual

| | Expected | Actual |
|---|---|---|
| Parser | Reject entry_count > (payload_remaining / min_entry_size) | Blindly allocates ~3 GiB |
| Result | Return error / skip atom | `std::bad_alloc` / OOM crash |

## Impact

- **Denial of Service**: Any process parsing an MP4 containing a crafted tfra atom
  can be crashed with a single small (~100-byte) file.
- **Affected binaries**: Any Bento4 tool that parses mfra boxes
  (mp42aac, mp4info, mp4dump, etc.).

## Suggested Fix

Before calling `SetItemCount`, validate that `entry_count` is consistent with the
remaining atom payload:

```cpp
AP4_UI32 max_entries = (size - AP4_FULL_ATOM_HEADER_SIZE - 12) / min_entry_size;
if (entry_count > max_entries) {
    return;  // or set entry_count = 0 and flag an error
}
m_Entries.SetItemCount(entry_count);
```

where `min_entry_size` is at least 8 bytes (two 4-byte fields for version-0 time
and moof_offset) plus 3 bytes for the three length-1 counters = 11 bytes.

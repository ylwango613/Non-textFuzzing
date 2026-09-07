# VULN 003 PoC Notes

## Vulnerability Summary

**File**: `Source/C++/Core/Ap4StscAtom.cpp`
**Function**: `AP4_StscAtom::AP4_StscAtom(AP4_UI32, AP4_ByteStream&)`
**Type**: OOB Read — wrong header constant causes box boundary crossing

## Root Cause

The stsc atom is a FullBox (version + flags = 4 extra bytes), so its header is 12 bytes
(`AP4_FULL_ATOM_HEADER_SIZE`). However, the bounds check uses `AP4_ATOM_HEADER_SIZE` (8 bytes).

With a crafted stsc box of `size=24, entry_count=1`:

| Check | Formula | Result |
|-------|---------|--------|
| Correct | `(24 - 12 - 4) / 12 = 0 < 1` | REJECT (entry doesn't fit) |
| Actual (buggy) | `(24 - 8 - 4) / 12 = 1 >= 1` | PASS (entry appears to fit) |

After the check passes, the parser:
1. Allocates 12 bytes for 1 entry
2. Calls `stream.Read(buffer, 12)` — but only 8 bytes remain in the stsc box
3. Reads 4 bytes beyond the stsc box boundary from the next box (stco)

## PoC Construction

The crafted MP4 has a stbl containing:
- `stsd` (full atom, 0 entries)
- `stts` (full atom, 0 entries)
- **`stsc` (size=24, entry_count=1, only 8 bytes of entry data)**
  - Contains: first_chunk=1, samples_per_chunk=1
  - Missing: sample_description_index (4 bytes)
- `stco` (full atom, 0 entries, size=16 = 0x00000010)
  - The first 4 bytes of stco (`\x00\x00\x00\x10` = 16) are read as `sample_description_index`
- `stsz` (full atom)

## Expected Behavior

The stsc entry will be parsed with:
- `first_chunk = 1`
- `samples_per_chunk = 1`
- `sample_description_index = 16` (read from stco's size field, out-of-bounds from stsc)

When mp42aac later accesses the sample description table using this index (16), it may:
- Access `desc[16-1]` = `desc[15]` on a table with 0 entries → invalid pointer dereference
- Or if `sample_description_index = 0` were read (e.g., from zeroed memory), `desc[0-1]`
  with unsigned arithmetic wraps to `desc[0xFFFFFFFF]` → definite crash

## Observation

Because the OOB read crosses into an adjacent, mapped region of the file buffer rather
than unmapped memory, ASAN's heap/stack sanitizers may not flag the read itself.
The observable effect is likely a logical error: a wrong `sample_description_index`
propagating downstream, potentially causing a NULL dereference or assertion failure
when the atom table is indexed with an out-of-range value.

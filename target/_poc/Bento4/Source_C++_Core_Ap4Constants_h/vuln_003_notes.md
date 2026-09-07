# VULN 003 PoC Notes

## Vulnerability

**Location**: `AP4_TrunAtom::AP4_TrunAtom()` in Bento4 (around line 127)
**Type**: Unbounded heap allocation leading to DoS (std::bad_alloc) on 64-bit or heap overflow on 32-bit.

## Root Cause

The trun (track run) atom constructor reads a 32-bit `sample_count` field directly from the stream and calls:

```cpp
m_Entries.SetItemCount(sample_count);
```

`sizeof(AP4_TrunAtom::Entry) == 16`. With `sample_count = 0x10000001`, this requests:
`0x10000001 * 16 = 0x100000010 bytes ≈ 4 GiB`

No bounds check is performed before the allocation, so on a 64-bit system `std::bad_alloc` is thrown, crashing the process.

## Trigger Path

```
main()
  -> AP4_File::AP4_File()
  -> AP4_AtomFactory::CreateAtomFromStream()
  -> AP4_TrunAtom::Create()
  -> AP4_TrunAtom::AP4_TrunAtom()   <-- crash here
```

## File Structure

The PoC constructs a minimal but structurally valid fragmented MP4:

```
ftyp  (file type)
moov  (movie header, minimal stbl, mvex/trex for fragmented support)
moof  (movie fragment)
  mfhd (fragment sequence number)
  traf (track fragment)
    tfhd (track fragment header, flags=0)
    trun (track run) <- MALICIOUS: sample_count=0x10000001, flags=0
mdat  (empty media data)
```

The `trun` box is 16 bytes:
- size=16, type='trun', version=0, flags=0x000000, sample_count=0x10000001

With `flags=0`, no optional fields (data_offset, first_sample_flags, per-sample arrays) are present, so the box is self-consistent in terms of byte count. The large `sample_count` value is only consumed when the constructor tries to pre-allocate the entry array.

## Expected Behavior

- **64-bit ASAN build**: `std::bad_alloc` → program terminates with exit code != 0. ASAN may report the exception or an allocation failure. The process reliably crashes/terminates.
- **32-bit build**: potential heap overflow if the allocator wraps around.

## PoC Generation

`vuln_003_gen.py` uses only Python `struct` and `bytes` — no native code compiled. Output file: `vuln_003.mp4`.

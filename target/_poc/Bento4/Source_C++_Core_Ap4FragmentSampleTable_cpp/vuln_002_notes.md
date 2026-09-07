# VULN 002 PoC Notes

## Vulnerability Summary

**Title**: Unchecked trun sample_count causes integer overflow in EnsureCapacity → heap OOB write in AP4_TrunAtom constructor loop (32-bit)

**Affected component**: `AP4_TrunAtom` constructor in `Source/C++/Core/Ap4TrunAtom.cpp`

## Root Cause

`AP4_TrunAtom`'s stream-parsing constructor reads `sample_count` from the MP4 bitstream without validating it against the atom's declared byte size. The code then calls `EnsureCapacity(sample_count)` which computes `sample_count * sizeof(Entry)`.

On 32-bit builds:
- `0x10000000 * 16 = 0x100000000` overflows to 0 mod 2^32
- `new Entry[0]` succeeds (allocates 0 bytes), but `m_AllocatedCount` is set to `0x10000000`
- The loop then immediately writes to `m_Entries[0]` in a 0-byte allocation → heap OOB write

On 64-bit builds:
- `new Entry[0x10000000]` = `new Entry[268435456]` = allocating ~4 GB
- `std::bad_alloc` is thrown → crash (DoS)

## PoC Approach

The generated MP4 (`vuln_002.mp4`) contains:
1. **ftyp** - file type box (brand: mp42)
2. **moov** - minimal movie box with one audio track (trak with mdhd/hdlr/minf/stbl, all empty)
3. **moof** - movie fragment:
   - **mfhd** - sequence_number=1
   - **traf** - track fragment:
     - **tfhd** - track_id=1, no optional fields
     - **trun** - `sample_count=0x10000000`, `flags=0x0201` (data_offset + sample_size_present)
       - Only 1 actual sample_size entry (4 bytes) is written in the atom body
       - The atom claims `sample_count=0x10000000` but provides far fewer bytes
4. **mdat** - minimal media data

## Expected Behavior

- **64-bit system (ASAN build)**: `std::bad_alloc` thrown when trying to allocate ~4 GB for entries → `terminate called after throwing an instance of 'std::bad_alloc'` → process terminates → VERIFIED_CRASH
- **32-bit system (ASAN build)**: Integer overflow in `EnsureCapacity` produces 0-byte allocation; first loop iteration writes out-of-bounds → ASAN reports `heap-buffer-overflow` → VERIFIED_CRASH

## Trigger Condition

The trun atom's `flags=0x0201` ensures:
- `AP4_TRUN_FLAG_DATA_OFFSET` (0x0001): data_offset field is present
- `AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT` (0x0200): per-sample `sample_size` is read in the constructor loop

The loop `for (unsigned int i=0; i<sample_count; i++)` tries to read `sample_size` from the stream for each of the 0x10000000 claimed samples, but the underlying atom byte buffer only has data for 1 sample entry. On 64-bit, the allocation itself crashes before the loop runs.

## Files

- `vuln_002_gen.py` - Generates the malicious MP4
- `vuln_002_run.sh` - Runs the PoC and captures output/ASAN logs
- `vuln_002.mp4` - Generated malicious MP4 (created by gen.py)
- `vuln_002_result.txt` - mp42aac output + ASAN error grep
- `asan_002.log.*` - ASAN log file(s)
- `vuln_002_status.txt` - Final status (VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED)

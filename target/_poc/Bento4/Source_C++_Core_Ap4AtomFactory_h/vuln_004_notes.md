# VULN 004 – AP4_TrunAtom: No bounds check on file-controlled `sample_count` → unbounded SetItemCount → heap OOB

## Vulnerability Summary

**Function**: `AP4_TrunAtom::AP4_TrunAtom()` (constructor)  
**Binary**: `mp42aac`  
**Trigger path**: `mp42aac input.mp4 → AP4_AtomFactory::CreateAtomFromStream()` (in context `moof/traf`) `→ AP4_TrunAtom::Create(size, stream)` `→ new AP4_TrunAtom(size, version, flags, stream)`

## Root Cause

In `AP4_TrunAtom::AP4_TrunAtom()`, the parser reads `sample_count` from the stream (a 4-byte big-endian field in the trun box) and passes it directly to `SetItemCount()` on the internal `AP4_Array<AP4_TrunAtom::Entry>` without any bounds check against the actual remaining box size. When `flags` has at least one sample-field bit set (e.g., `sample_size_present` = `0x200`), the code allocates `sample_count * sizeof(Entry)` bytes of memory. With `sample_count = 0x10000001`, each Entry containing 4 UI32 fields (16 bytes), the required allocation is approximately `0x10000001 * 16 ≈ 4 GB`, causing `std::bad_alloc`.

## PoC Construction

The PoC constructs a minimal fragmented MP4 with:
- `ftyp` box (brand `iso5`)
- `moov` box (minimal: `mvhd` + `trak` with `soun` handler + `mvex/trex`)
- `moof` box containing:
  - `mfhd` (sequence_number=1)
  - `traf` containing:
    - `tfhd` (track_id=1, no flags)
    - `trun` with:
      - `version=0`, `flags=0x201` (data_offset present + sample_size present)
      - `sample_count=0x10000001` (triggers the huge allocation)
      - `data_offset=8`
      - 1 fake sample entry (sample_size=1)
- `mdat` box (empty)

## Expected Crash

On ASAN builds: `std::bad_alloc` exception (denial of service). The process terminates with a C++ exception because the heap cannot satisfy a ~4 GB allocation request.

## Files

- `vuln_004_gen.py`: Python script to generate the malformed `vuln_004.mp4`
- `vuln_004_run.sh`: Shell script to run the PoC against `mp42aac`
- `vuln_004.mp4`: Generated malformed MP4 file
- `vuln_004_result.txt`: Captured output from the run
- `asan.log.*`: ASAN logs (if any)

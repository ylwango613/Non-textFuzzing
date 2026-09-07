# VULN 001 — AP4_CttsAtom Integer Overflow (Bento4 / mp42aac)

## Vulnerability Summary

**File**: `Ap4CttsAtom.cpp`, lines 77–97  
**Class**: `AP4_CttsAtom`  
**CWE**: CWE-190 (Integer Overflow or Wraparound)  
**Impact**: Heap corruption / out-of-bounds write / `std::bad_alloc` DoS

## Root Cause

The ctts (Composition Time-to-Sample) box parser reads `entry_count` from the
file as a 32-bit unsigned integer (`AP4_UI32`) with no upper-bound check:

```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);
// allocates entry_count * sizeof(AP4_CttsTableEntry) bytes
// sizeof(AP4_CttsTableEntry) == 8
AP4_Array<AP4_CttsTableEntry> entries(entry_count);   // entry_count * 8
```

When `entry_count >= 0x20000000`:

```
entry_count * 8 >= 0x100000000
```

On 32-bit arithmetic this wraps to 0 (or a small value), so the heap allocation
is far smaller than the subsequent loop expects, causing:

- **Heap buffer overflow** (writes past the allocated region), or  
- **`std::bad_alloc`** if the wrapped size is still large enough to fail,  
- **`std::terminate`** / crash depending on the build's exception handling.

## PoC Structure

The generated `vuln_001.mp4` is a minimal but structurally valid MP4 that
places the crafted ctts box inside the sample table (stbl) of a single audio
track:

```
ftyp (mp42)
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr (soun)
      minf
        smhd
        dinf → dref → url
        stbl
          stsd  (0 entries)
          stts  (0 entries)
          stsc  (0 entries)
          stsz  (0 entries)
          stco  (0 entries)
          ctts  ← entry_count = 0x20000000, 0 actual entries
```

The ctts box declares 536,870,912 entries but provides zero bytes of entry
data.  The parser trusts the declared count, allocates memory using
`entry_count * 8` (which overflows), and then reads past the allocation.

## Expected Behaviour

| Build type | Expected outcome |
|------------|-----------------|
| ASAN build | `AddressSanitizer: heap-buffer-overflow` or `bad_alloc` / OOM abort |
| Release build | `SIGSEGV` or silent heap corruption |
| Both | Non-zero exit code |

## Reproduction

```bash
bash vuln_001_run.sh
cat vuln_001_result.txt
```

The run script generates the MP4, executes `mp42aac` under ASAN, and collects
diagnostic output to `vuln_001_result.txt`.

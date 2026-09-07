# VULN 001 – AP4_CttsAtom Integer Overflow → Heap Buffer Over-Read

## Overview

**Target:** Bento4 `mp42aac` binary (ASAN + UBSAN build)  
**Component:** `AP4_CttsAtom::AP4_CttsAtom()` in `Source/C++/Core/Ap4CttsAtom.cpp` (lines 77–97)  
**CWE:** CWE-190 (Integer Overflow) → CWE-125 (Out-of-Bounds Read) / CWE-122 (Heap Buffer Overflow)

---

## Vulnerability Description

The constructor `AP4_CttsAtom::AP4_CttsAtom()` reads a 32-bit `entry_count` from the
input stream without any bounds check, then uses it in the following sequence:

```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);
m_Entries.SetItemCount(entry_count);                     // (1)
unsigned char* buffer = new unsigned char[entry_count*8]; // (2)
AP4_Result result = stream.Read(buffer, entry_count*8);  // (3)
// ... error check ...
for (unsigned i = 0; i < entry_count; i++) {
    m_Entries[i].m_SampleCount  = AP4_BytesToUInt32BE(&buffer[i*8  ]); // (4)
    m_Entries[i].m_SampleOffset = AP4_BytesToUInt32BE(&buffer[i*8+4]); // (5)
}
```

### Integer Overflow

When `entry_count = 0x20000000`:

- `entry_count * 8 = 0x20000000 * 8 = 0x100000000`
- This is computed as a 32-bit unsigned multiplication, overflowing to **0**.
- `new unsigned char[0]` allocates a 0-byte buffer but returns a **non-NULL pointer**.

### Heap Buffer Over-Read

- `stream.Read(buffer, 0)` reads 0 bytes into the 0-byte buffer — no data is populated.
- The loop runs `entry_count = 0x20000000` times (536,870,912 iterations).
- Each iteration accesses `buffer[i*8]` and `buffer[i*8+4]` — both are **out-of-bounds**
  for the 0-byte allocation, constituting a massive heap buffer over-read (CWE-125).

### Additional: OOM / NULL Pointer Dereference

- `m_Entries.SetItemCount(0x20000000)` attempts to allocate an array of
  536,870,912 entries × sizeof(AP4_CttsTableEntry) bytes = several GB.
- On a 64-bit system this may fail with OOM, producing a NULL `m_Entries` backing array.
- Subsequent `m_Entries[i]` accesses then dereference a NULL pointer (CWE-476).

---

## Trigger Path

```
mp42aac main()
  → AP4_File::AP4_File()
    → AP4_DefaultAtomFactory::CreateAtomFromStream()
      → reads 'ctts' box from stbl container
        → AP4_CttsAtom::Create(size, stream)
          → new AP4_CttsAtom(size=20, version=0, flags=0, stream)
            → stream.ReadUI32(entry_count)  // entry_count = 0x20000000
            → m_Entries.SetItemCount(0x20000000)  // may OOM
            → new unsigned char[0x20000000 * 8]   // overflows to new char[0]
            → loop over 0x20000000 entries → OOB heap read ← CRASH HERE
```

---

## PoC Construction

The malicious MP4 contains a minimal but structurally valid atom hierarchy:

```
ftyp (isom)
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr (soun)
      minf
        smhd
        dinf
          dref (url, self-contained)
        stbl
          stsd (0 entries)
          stts (0 entries)
          stsc (0 entries)
          ctts ← MALICIOUS (size=20, entry_count=0x20000000)
          stsz (0 samples)
          stco (0 chunks)
```

### Malicious ctts Atom Layout (20 bytes)

| Offset | Bytes | Field         | Value              |
|--------|-------|---------------|--------------------|
| 0      | 4     | size          | 0x00000014 (20)    |
| 4      | 4     | type          | 0x63747473 ('ctts') |
| 8      | 4     | version+flags | 0x00000000          |
| 12     | 4     | entry_count   | 0x20000000          |
| 16     | 4     | (padding)     | 0x00000000          |

The declared `entry_count` of `0x20000000` with no actual entry data in the
stream triggers the integer overflow and subsequent heap buffer over-read.

---

## Files

| File               | Description                                     |
|--------------------|-------------------------------------------------|
| `vuln_001_gen.py`  | Python script that constructs the malicious MP4 |
| `vuln_001.mp4`     | Generated malicious input file                  |
| `vuln_001_run.sh`  | Shell script to run the PoC with ASAN           |
| `vuln_001_result.txt` | Captured output from the run               |
| `asan.log.*`       | ASAN sanitizer output (generated at runtime)   |
| `vuln_001_status.txt` | Verification status (VERIFIED_CRASH / etc.) |

---

## Expected ASAN Output

ASAN should report one of:
- `heap-buffer-overflow` at `AP4_BytesToUInt32BE` called from `AP4_CttsAtom` constructor
- `allocation-size-too-large` or `out-of-memory` at `SetItemCount` or `new unsigned char[]`
- UBSAN: `runtime error: signed integer overflow` or `unsigned integer overflow`

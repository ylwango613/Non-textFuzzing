# VULN 001 – AP4_CttsAtom Integer Overflow

## Summary

**Target binary**: `mp42aac` (Bento4)  
**Vulnerable function**: `AP4_CttsAtom::AP4_CttsAtom()`  
**Root cause**: Integer overflow in `entry_count * 8` (or equivalent `sizeof` multiplication) when allocating a buffer to hold ctts entries. With `entry_count = 0x20000001`, the multiplication overflows a 32-bit integer to a small value, causing an undersized allocation followed by a heap-buffer-overflow write; on 64-bit the raw value (~536M * 8 ≈ 4 GB) triggers `std::bad_alloc`.

## Trigger Path

```
mp42aac input.mp4
  → AP4_File
  → AP4_AtomFactory::CreateAtomsFromStream()
  → AP4_CttsAtom::Create(size, stream)
  → new AP4_CttsAtom(size, version, flags, stream)
      reads entry_count = 0x20000001
      allocates: new unsigned char[entry_count * 8]
                           ^^^^^^^^^^^^^^^^^^^^^^^^^
                           overflow / enormous alloc
```

## ctts Box Layout (crafted)

| Field         | Value             | Notes                          |
|---------------|-------------------|--------------------------------|
| size          | 0x18 (24 bytes)   | Header(12) + entry_count(4) + 1 entry(8) |
| type          | `ctts`            |                                |
| version       | 0x00              |                                |
| flags         | 0x000000          |                                |
| entry_count   | **0x20000001**    | Big-endian, ~536 M entries     |
| sample_count  | 0x00000001        | 1 real entry present           |
| sample_offset | 0x00000000        |                                |

Declared entries: 536,870,913  
Declared allocation: ~4 GB (64-bit OOM) or overflow to small size (32-bit heap OOB)

## MP4 Box Hierarchy

```
ftyp
moov
  mvhd  (version=0)
  trak
    tkhd  (version=0)
    mdia
      mdhd  (version=0)
      hdlr  (soun handler)
      minf
        smhd
        dinf
          dref (url, self-contained)
        stbl
          stsd  (0 entries)
          stts  (0 entries)
          ctts  ← TRIGGER
```

## Expected Behaviour

- **64-bit ASAN / release**: `std::bad_alloc` → `abort()` or `terminate()`; exit code ≠ 0.
- **32-bit ASAN**: integer overflow → undersized buffer → heap-buffer-overflow on subsequent element writes; ASAN reports `heap-buffer-overflow`.

## Files

| File                 | Description                        |
|----------------------|------------------------------------|
| `vuln_001_gen.py`    | Generates `vuln_001.mp4`           |
| `vuln_001.mp4`       | Crafted MP4 input                  |
| `vuln_001_run.sh`    | Runs mp42aac and collects results  |
| `asan.log.*`         | ASAN output (if ASAN build)        |
| `vuln_001_status.txt`| VERIFIED_CRASH / UNVERIFIED / ERROR |
| `vuln_001_notes.md`  | This file                          |

# VULN 001 — AP4_Stz2Atom Integer Overflow → Heap Buffer Over-read

## Vulnerability Summary

- **File**: `Source/C++/Core/Ap4Stz2Atom.cpp`
- **Function**: `AP4_Stz2Atom::AP4_Stz2Atom()`
- **Type**: 32-bit unsigned integer overflow → heap buffer over-read

## Root Cause

In the `AP4_Stz2Atom` constructor, `table_size` is computed as:

```cpp
AP4_UI32 table_size = (sample_count * m_FieldSize + 7) / 8;
```

With `field_size=16` and `sample_count=0x10000000`:

- `0x10000000 * 16 = 0x100000000`
- In 32-bit arithmetic this overflows to `0`
- `(0 + 7) / 8 = 0` so `table_size = 0`

A bounds check of the form `(table_size + 8) > payload_size` is bypassed because `table_size=0` makes the check trivially pass even with a minimal payload.

Then `new unsigned char[0]` allocates a zero-byte buffer, and the subsequent loop iterates `sample_count` (0x10000000 = 268,435,456) times reading entries from this 0-byte buffer — a massive heap buffer over-read.

## PoC Approach

The crafted MP4 (`vuln_001.mp4`) contains a minimal but parseable structure:

```
ftyp
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr (handler_type='soun')
      minf
        smhd
        dinf
          dref
        stbl
          stsd
          stts (entry_count=0)
          stsc (entry_count=0)
          stsz (sample_size=0, sample_count=0)
          stco (entry_count=0)
          stz2 ← MALICIOUS BOX
```

The malicious `stz2` box (20 bytes total):
- `field_size = 16`
- `sample_count = 0x10000000`
- No entry data provided

## Expected Behavior

When mp42aac parses this file:
1. It descends into `moov → trak → mdia → minf → stbl`
2. It encounters the `stz2` box and calls `AP4_Stz2Atom::AP4_Stz2Atom()`
3. The integer overflow occurs: `table_size = 0`
4. A zero-byte buffer is allocated
5. The loop attempts to read 0x10000000 entries from it
6. ASAN should report: **heap-buffer-overflow** (over-read)
7. Or the process may crash with a segfault on OOB memory access

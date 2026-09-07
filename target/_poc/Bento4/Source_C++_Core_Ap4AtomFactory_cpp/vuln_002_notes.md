# VULN 002 — AP4_Stz2Atom table_size 32-bit Integer Overflow (Heap OOB Read)

## Vulnerability Summary

**File**: `Source/C++/Core/Ap4Stz2Atom.cpp`, lines ~90–92  
**Binary**: `mp42aac`  
**Class**: Integer overflow → heap out-of-bounds read

## Root Cause

In `AP4_Stz2Atom` constructor, the table size is computed as:

```cpp
AP4_Size table_size = (sample_count * m_FieldSize + 7) / 8;
```

When `m_FieldSize = 8` (field_size byte in the box) and `sample_count = 0x20000000`:

- Multiplication: `0x20000000 * 8 = 0x100000000`
- This overflows a 32-bit `AP4_UI32`/`AP4_Size` to **0**
- So `table_size = (0 + 7) / 8 = 0`

The subsequent bounds check:

```cpp
if ((table_size + 8) > size) return AP4_ERROR_INVALID_FORMAT;
```

becomes `8 > size`. For any box of size >= 8 bytes (minimum valid stz2 is 21 bytes), this **passes** — the check is bypassed.

Then:
1. `new unsigned char[0]` allocates a 0-byte buffer
2. `stream.Read(buffer, 0)` reads 0 bytes (harmless)
3. The for loop iterates `0x20000000` (536 million) times, reading `buffer[i]` → **heap out-of-bounds read** from the very first iteration

Additionally, `m_Entries.SetItemCount(sample_count)` attempts to allocate `0x20000000 * sizeof(AP4_UI32)` ≈ 2GB of memory, which may also cause failure.

## PoC Construction

### Trigger Conditions

- Box type: `stz2`  
- `field_size` byte = `0x08` (8 bits per entry)  
- `sample_count` = `0x20000000` (little data in box, violating declared count)  
- Box declared size: 21 bytes (minimal valid stz2 without entry data)

### MP4 Structure

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
          stsd (empty)
          stts (empty)
          stz2 [MALICIOUS: field_size=8, sample_count=0x20000000, no entry data]
          stsc (empty)
          stco (empty)
```

### stz2 Box Layout (21 bytes total)

| Offset | Size | Value | Description |
|--------|------|-------|-------------|
| 0 | 4 | `0x00000015` | Box size = 21 |
| 4 | 4 | `stz2` | Box type |
| 8 | 1 | `0x00` | Version = 0 |
| 9 | 3 | `0x000000` | Flags = 0 |
| 12 | 4 | `0x00000000` | Reserved |
| 16 | 1 | `0x08` | field_size = 8 |
| 17 | 4 | `0x20000000` | sample_count = 536870912 |

## Trigger Path

```
mp42aac main()
  → AP4_File::AP4_File(stream)
    → AP4_AtomFactory::CreateAtomFromStream()
      → AP4_Stz2Atom::Create(size=21, stream)
        → new AP4_Stz2Atom(size, version, flags, stream)
          → table_size = (0x20000000 * 8 + 7) / 8  [OVERFLOW → 0]
          → if (0 + 8) > 21 → false [CHECK BYPASSED]
          → new unsigned char[0]  [0-byte allocation]
          → for (i=0; i < 0x20000000; i++) ... buffer[i]  [OOB READ]
```

## Expected ASAN Output

With AddressSanitizer, the expected report is:
- `heap-buffer-overflow` on a READ
- Access past end of a 0-byte heap allocation
- Stack trace pointing into `AP4_Stz2Atom` constructor

## Impact

- **Confidentiality**: potential information disclosure via OOB heap read
- **Stability**: near-certain process crash (SIGSEGV or ASAN abort)
- **Exploitability**: OOB read with attacker-controlled iteration count; heap layout dependent

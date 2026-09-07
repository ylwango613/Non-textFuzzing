# VULN-002: AP4_Stz2Atom Integer Overflow in table_size

## Vulnerability Summary

**Component:** Bento4 / AP4 library  
**File:** `Source/C++/Core/Ap4Stz2Atom.cpp`, lines 88–121  
**Binary:** `mp42aac` (and any Bento4 consumer that parses stz2 boxes)  
**Class:** Integer overflow leading to heap buffer over-read/over-write  

## Root Cause

The `stz2` (compact sample size) box parser in `AP4_Stz2Atom::AP4_Stz2Atom()` reads a 32-bit `sample_count` from the file and then computes `table_size` as:

```cpp
AP4_Cardinal sample_count = m_SampleCount;           // 0x40000000
m_Entries.SetItemCount(sample_count);                // (A) tries to alloc huge array
unsigned int table_size = (sample_count*m_FieldSize+7)/8; // (B) 32-bit overflow -> 0
if ((table_size+8) > size) return;                   // (C) bounds check bypassed
unsigned char* buffer = new unsigned char[table_size]; // (D) 0-byte allocation
stream.Read(buffer, table_size);                     // (E) reads 0 bytes
// (F) loop iterates 0x40000000 times, writing to 0-byte m_Entries and reading 0-byte buffer
for (unsigned int i=0; i<sample_count; i++) {
    m_Entries[i] = (buffer[i/2]>>4)&0x0F;           // HEAP BUFFER OVERFLOW
}
```

**Overflow chain with `field_size=4`, `sample_count=0x40000000`:**

| Step | Expression | Value |
|------|-----------|-------|
| A | `EnsureCapacity(0x40000000)` → `::operator new(0x40000000 * 4)` | `operator new(0x100000000)` → overflows to `operator new(0)` → 0-byte alloc |
| B | `0x40000000 * 4` as `unsigned int` | `0x100000000` → overflows to `0` |
| C | `(0 + 8) > 20` | `false` → check **passes** |
| D | `new unsigned char[0]` | Valid non-null pointer to 0 bytes |
| E | `stream.Read(buffer, 0)` | Reads 0 bytes, succeeds |
| F | Loop `i = 0 .. 0x3FFFFFFF` | Writes to 0-byte `m_Entries`, reads from 0-byte `buffer` → **heap-buffer-overflow** |

## Trigger Conditions

- MP4 file containing an `stz2` box
- `field_size = 4` (other values: 8 or 16 produce different overflow magnitudes)
- `sample_count = 0x40000000` (value chosen so `sample_count * field_size` overflows a 32-bit int to 0)
- The `stz2` box does not need to contain any actual entry data

## Impact

- **32-bit builds:** Heap buffer over-read and over-write in the sample entry loop — potential for code execution or information disclosure
- **64-bit builds:** Double integer overflow path:
  1. `EnsureCapacity` attempts to allocate `0x100000000` bytes → system may OOM/abort (DoS)
  2. If the allocator silently returns for `operator new(0)` (implementation-defined), the subsequent loop writes 0x40000000 entries to a 0-byte buffer → heap-buffer-overflow

## PoC File Structure

```
ftyp (28 bytes)
moov (441 bytes)
  mvhd (108 bytes)
  trak (325 bytes)
    tkhd (92 bytes)
    mdia (225 bytes)
      mdhd (32 bytes)
      hdlr (33 bytes) — handler_type='soun'
      minf (152 bytes)
        smhd (16 bytes)
        dinf (36 bytes)
          dref (28 bytes) — 1 url entry
        stbl (92 bytes)
          stsd (16 bytes) — 0 entries
          stts (16 bytes) — 0 entries
          stsc (16 bytes) — 0 entries
          stz2 (20 bytes) — MALICIOUS: field_size=4, sample_count=0x40000000
          stco (16 bytes) — 0 entries
Total: 469 bytes
```

## Expected Behavior

When `mp42aac` opens the PoC file:
1. The parser navigates `moov → trak → mdia → minf → stbl → stz2`
2. `AP4_Stz2Atom::Create()` is called
3. `AP4_Stz2Atom::AP4_Stz2Atom(size=20, ...)` constructor runs
4. **ASAN reports `heap-buffer-overflow`** on the first write to `m_Entries[0]`
   (or `std::bad_alloc` / process abort if the OS refuses the 4 GB allocation before the overflow path)

## Fix Recommendation

Add an explicit bounds check on `sample_count` before computing `table_size`:

```cpp
// Guard: reject unreasonably large sample counts
AP4_UI64 table_size_safe = ((AP4_UI64)sample_count * m_FieldSize + 7) / 8;
if (table_size_safe > size) return;
unsigned int table_size = (unsigned int)table_size_safe;
if ((table_size + 8) > size) return;
```

And validate `sample_count` against the remaining box size before calling `SetItemCount`.

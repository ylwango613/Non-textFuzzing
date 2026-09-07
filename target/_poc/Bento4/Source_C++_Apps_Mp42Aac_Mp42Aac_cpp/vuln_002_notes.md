# VULN-002: AP4_Stz2Atom Integer Overflow leading to Heap OOB Read

## Vulnerability Summary

- **File**: `Bento4/Source/C++/Core/Ap4Stz2Atom.cpp`, lines 88–121
- **CWE**: CWE-190 (Integer Overflow or Wraparound), CWE-125 (Out-of-bounds Read)
- **Binary**: `mp42aac`
- **Trigger**: Crafted `.mp4` with a `stz2` box having `field_size=16`, `sample_count=0x10000000`

---

## Root Cause Analysis

In `AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)`:

```cpp
AP4_Cardinal sample_count = m_SampleCount;         // 0x10000000
m_Entries.SetItemCount(sample_count);
unsigned int table_size = (sample_count * m_FieldSize + 7) / 8;
// With m_FieldSize=16, sample_count=0x10000000:
//   0x10000000 * 16 = 0x100000000 -> wraps to 0 in 32-bit unsigned
//   table_size = (0 + 7) / 8 = 0
if ((table_size + 8) > size) return;
// size=20, check: (0+8)>20 -> 8>20 -> FALSE -> we do NOT return
unsigned char* buffer = new unsigned char[table_size]; // new unsigned char[0]
AP4_Result result = stream.Read(buffer, table_size);   // Read 0 bytes -> success
// ...
case 16:
    for (unsigned int i = 0; i < sample_count; i++) {
        m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i * 2]);
        // FIRST ITERATION: &buffer[0] -> OOB read on 0-byte allocation!
    }
```

### Integer Overflow Chain

1. `sample_count = 0x10000000` (268,435,456)
2. `m_FieldSize = 16`
3. `sample_count * m_FieldSize` computed as 32-bit: `0x10000000 * 16 = 0x100000000` wraps to `0x00000000`
4. `table_size = (0 + 7) / 8 = 0`
5. Bounds check `(0 + 8) > 20` evaluates to `false` — check is bypassed
6. `new unsigned char[0]` returns a valid but zero-length heap allocation
7. `stream.Read(buffer, 0)` succeeds (reads 0 bytes)
8. Loop iterates from `i=0` to `0x10000000-1`, reading `buffer[0]`, `buffer[2]`, ... all OOB

---

## Trigger Conditions

- Box: `stz2` inside `moov/trak/mdia/minf/stbl`
- `field_size` byte = `0x10` (16)
- `sample_count` field = `0x10000000` (big-endian)
- Box declared size = 20 (minimal valid header, no entries data)
- The bounds check `(table_size+8) > size` is bypassed because `table_size=0` and `8 < size`

---

## PoC MP4 Structure

```
ftyp [20 bytes]
moov [container]
  mvhd [108 bytes]
  trak [container]
    tkhd [92 bytes]
    mdia [container]
      mdhd [32 bytes]
      hdlr [33 bytes] (handler: 'soun')
      minf [container]
        smhd [16 bytes]
        dinf [container]
          dref [28 bytes]
        stbl [container]
          stsd [52 bytes]
          stts [16 bytes]
          stz2 [20 bytes] <-- MALICIOUS: field_size=16, sample_count=0x10000000
          stco [16 bytes]
mdat [8 bytes, empty]
```

---

## Expected ASAN Output

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... 
READ of size 2 at 0x... thread T0
    #0 0x... in AP4_BytesToUInt16BE ...
    #1 0x... in AP4_Stz2Atom::AP4_Stz2Atom ...
    #2 0x... in AP4_Stz2Atom::Create ...
```

---

## Impact

- **Confidentiality**: Out-of-bounds heap read; may leak adjacent heap data
- **Stability**: Crash on first read (ASAN), likely also crash without ASAN due to invalid memory access
- **Exploitability**: OOB read on a heap allocation adjacent to other objects; dependent on heap layout
- **Attack vector**: Processing an untrusted MP4 file (e.g., `mp42aac malicious.mp4 out.aac`)

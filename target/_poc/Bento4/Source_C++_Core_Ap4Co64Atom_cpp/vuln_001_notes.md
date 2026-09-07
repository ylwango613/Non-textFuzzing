# VULN 001 — AP4_Co64Atom Integer Underflow (CWE-191)

## Affected File
`Bento4/Source/C++/Core/Ap4Co64Atom.cpp`, lines 78-81

## Vulnerability Mechanism

The `AP4_Co64Atom` stream-parsing constructor contains a size guard intended
to cap `m_EntryCount` to the number of 8-byte entries that actually fit
inside the declared atom size:

```cpp
stream.ReadUI32(m_EntryCount);
if (m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 8) {   // line 78
    m_EntryCount = (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 8;      // line 79
}
m_Entries = new AP4_UI64[m_EntryCount];                              // line 81
```

All variables are unsigned 32-bit (`AP4_UI32`).  When `size` equals
`AP4_FULL_ATOM_HEADER_SIZE` (12), the subtraction wraps:

```
(12 - 12 - 4) / 8  ==  0xFFFFFFFC / 8  ==  0x1FFFFFFF   (536,870,911)
```

Instead of capping `m_EntryCount` to 0 (no payload space), the corrupted
threshold allows any value up to 536 million entries.

## How the PoC Triggers It

`vuln_001.mp4` is a minimal valid MP4 with the following atom hierarchy:

```
ftyp  (20 bytes)
moov
  trak
    tkhd  (92 bytes)
    mdia
      mdhd  (32 bytes)
      hdlr  (45 bytes, handler='soun')
      minf
        smhd  (16 bytes)
        dinf  (36 bytes)
        stbl
          stsd  (16 bytes, entry_count=0)
          stts  (16 bytes, entry_count=0)
          stsc  (16 bytes, entry_count=0)
          stsz  (20 bytes, sample_count=0)
          co64  (12 bytes, MALICIOUS — no entry_count stored)
          [132 bytes OOB data appended within stbl]
```

The `co64` atom declares `size = 12`, which exactly equals
`AP4_FULL_ATOM_HEADER_SIZE`.  The physical box contains only the 12-byte
full-atom header (size + type + version + flags).  There is no room for the
`entry_count` field inside the box.

The 132 bytes appended within `stbl` after `co64` serve as the controlled
out-of-bounds payload:

| Offset from co64 end | Content                        |
|----------------------|--------------------------------|
| +0 to +3             | `0x00000010` — entry_count = 16|
| +4 to +131           | 16 × 8-byte chunk offsets (0)  |

Call chain:

```
mp42aac main()
  AP4_File(*input)
    AP4_DefaultAtomFactory::CreateAtomFromStream(...)  [for 'co64']
      AP4_Co64Atom::Create(size=12, stream)
        AP4_Atom::ReadFullHeader(stream, version, flags)   // reads 4 bytes
        AP4_Co64Atom::AP4_Co64Atom(size=12, 0, 0, stream)
          stream.ReadUI32(m_EntryCount)   // OOB: reads entry_count = 16
          guard: 16 > 0x1FFFFFFF?  No -> m_EntryCount stays 16
          new AP4_UI64[16]               // allocates 128 bytes (correct)
          for i in 0..15:               // OOB: reads 128 bytes past box end
            stream.ReadUI64(m_Entries[i])
```

The `m_Entries` allocation is itself valid (16 entries); the bug is that
the constructor reads `entry_count` and 128 bytes of entry data from outside
the declared atom boundary (OOB stream read), violating the atom framing
contract and potentially exposing data from adjacent atoms or file regions.

## Expected Output / Crash Behaviour

| Scenario                  | entry_count | Effect                                       |
|---------------------------|-------------|----------------------------------------------|
| OOB stream read (this PoC)| 16 (0x10)   | 132 bytes read past box; no memory crash     |
| OOM crash (alternative)   | 0x1FFFFFFF  | `new AP4_UI64[0x1FFFFFFF]` → bad_alloc/OOM  |

With `entry_count = 16`:
- ASAN will **not** fire a memory-safety alert because the reads go through
  the `AP4_FileByteStream` (OS file I/O), not through a heap buffer.
- `mp42aac` will likely exit with an error such as
  `ERROR: unable to parse sample description` or `ERROR: no audio track found`
  because the crafted file carries no sample descriptions (stsd entry_count=0).
- The vulnerability is still demonstrated: the guard calculation is bypassed
  and out-of-bounds stream data is consumed as chunk offsets.

With `entry_count = 0x1FFFFFFF` (change `OOB_ENTRY_COUNT` in gen.py):
- `new AP4_UI64[0x1FFFFFFF]` requests ~4 GB; this throws `std::bad_alloc`,
  which terminates the process (verified crash / OOM kill).

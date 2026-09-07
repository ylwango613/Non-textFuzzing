# VULN 001 – AP4_CttsAtom Integer Overflow → Heap-Buffer-Overflow

## Summary

The `AP4_CttsAtom` constructor in Bento4 reads `entry_count` (AP4_UI32) from the MP4
byte-stream without validating it against the actual remaining box size.  It then
allocates storage with an expression equivalent to `new unsigned char[entry_count * 8]`.
On a 32-bit multiplication, `entry_count = 0x20000001` causes

```
0x20000001 * 8 = 0x100000008  →  truncates to 8  (32-bit integer overflow)
```

so only **8 bytes** are heap-allocated.  The constructor then loops over
`entry_count` (0x20000001) iterations reading 8 bytes per entry, immediately
overflowing out of the tiny 8-byte buffer.

## Root Cause

- File: `Source/C++/Core/Ap4CttsAtom.cpp`
- Constructor: `AP4_CttsAtom::AP4_CttsAtom(AP4_UI32 size, AP4_UI08 version, AP4_UI32 flags, AP4_ByteStream& stream)`
- No check that `entry_count * 8 <= remaining_box_bytes` before allocation and loop.

## PoC Approach

A minimal, well-formed MP4 file is synthesised with Python's `struct` module
(no third-party libraries required):

```
ftyp (20 bytes)
moov
  trak
    tkhd  (version 0, 92 bytes)
    mdia
      mdhd  (version 0, 32 bytes)
      hdlr  (33 bytes, handler='soun')
      minf
        smhd  (16 bytes)
        dinf  (dref with one self-contained url  entry)
        stbl
          stsd / stts / stsc / stsz / stco  (empty, minimal)
          ctts  ← MALICIOUS BOX
```

The `ctts` box (24 bytes total) declares `entry_count = 0x20000001` but contains
only one real entry (8 bytes of dummy data).  When the parser reaches it:

1. `entry_count * 8` overflows 32-bit to **8** → allocates an 8-byte heap buffer.
2. The read loop iterates 0x20000001 times, reading 8 bytes each time.
3. On the **second** iteration, the read accesses 1 byte past the end of the
   8-byte allocation → **heap-buffer-overflow** detected by ASAN.

## Observed ASAN Output (truncated)

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000178
READ of size 1 at 0x502000000178 thread T0
    #0 AP4_CttsAtom::AP4_CttsAtom(…)   ← overflow happens here
    …
0x502000000178 is located 0 bytes to the right of 8-byte region [0x502000000170,0x502000000178)
allocated by thread T0 here:
    #1 AP4_CttsAtom::AP4_CttsAtom(…)   ← 8 bytes allocated here
```

The allocation site and the overflow site are both inside the same constructor,
confirming the 32-bit multiply overflow and the resulting under-sized buffer.

## Trigger Path

```
main()
  → AP4_File::AP4_File(AP4_ByteStream&, bool)
    → AP4_File::ParseStream(…)
      → AP4_AtomFactory::CreateAtomFromStream(…)
        → AP4_MoovAtom constructor → AP4_TrakAtom constructor
          → AP4_ContainerAtom::ReadChildren  (×4 levels for moov/trak/mdia/minf/stbl)
            → AP4_CttsAtom::Create(…)
              → AP4_CttsAtom::AP4_CttsAtom(…)  ← CRASH
```

## Impact

- **Heap-buffer-overflow** (read): can be turned into an out-of-bounds read
  spanning the heap, potentially leaking adjacent heap metadata.
- **DoS**: process aborts under ASAN; without ASAN the read likely continues
  until it hits unmapped memory (SIGSEGV) or until `stream.Read()` returns EOF,
  leaving the application in an undefined state.
- Any tool or application that calls `mp42aac` (or links `libap4`) against
  untrusted MP4 files is vulnerable.

## Fix Recommendation

Before the allocation loop, validate:
```cpp
if (entry_count > (remaining_payload_bytes / 8)) {
    return AP4_ERROR_INVALID_FORMAT;
}
```
where `remaining_payload_bytes = size - 12` (box size minus the 8-byte header
and the 4-byte version/flags field).

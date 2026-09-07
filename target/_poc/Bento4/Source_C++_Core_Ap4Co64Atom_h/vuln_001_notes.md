# VULN 001 - Integer Underflow in AP4_Co64Atom

## Classification

| Field | Value |
|-------|-------|
| CWE | CWE-191 (Integer Underflow) leading to CWE-770 (Allocation without Limits) |
| Affected file | `Bento4/Source/C++/Core/Ap4Co64Atom.cpp` |
| Affected lines | 77-84 |
| Affected binary | `mp42aac` |

## Root Cause

`AP4_Co64Atom::Create()` guards only against `size < AP4_FULL_ATOM_HEADER_SIZE` (12),
so a co64 box with `size == 12` reaches the private constructor.

The constructor computes the maximum allowed entry count as:

```cpp
// Ap4Co64Atom.cpp:78-80
if (m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 8) {
    m_EntryCount = (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 8;
}
```

All operands are `AP4_UI32` (unsigned 32-bit).  When `size == 12`:

```
(12u - 12u - 4u) / 8u
= (0u - 4u) / 8u          (unsigned underflow)
= 0xFFFFFFFC / 8
= 536870911                 (0x1FFFFFFF)
```

The guard therefore effectively accepts any `m_EntryCount <= 536870911`, rendering
it useless.

## Exploitation Mechanics

1. **Out-of-bounds read**: because the co64 box declares only 12 bytes (the full-atom
   header), the `stream.ReadUI32(m_EntryCount)` call at line 77 reads 4 bytes that lie
   *outside* the declared box boundary.  The attacker controls those bytes via whatever
   immediately follows the co64 box in the stream.

2. **Giant allocation**: with `m_EntryCount = 0x10000000` (268,435,456):
   ```cpp
   m_Entries = new AP4_UI64[m_EntryCount];   // 268435456 * 8 = 2,147,483,648 bytes
   ```
   This requests 2 GiB from the allocator.  Outcomes:
   - Systems with ASAN: `ASAN OOM` / `bad_alloc`
   - Systems without ASAN but with ulimits: `std::bad_alloc` → uncaught exception → abort
   - Systems with abundant RAM: successful 2 GiB allocation followed by an I/O loop
     attempting to fill the array from a truncated stream (stream exhaustion).

## PoC Structure

```
ftyp (24 B)
moov (409 B)
  mvhd (108 B)
  trak (293 B)
    tkhd (92 B)
    mdia (193 B)
      mdhd (32 B)
      hdlr (33 B)
      minf (120 B)
        smhd (16 B)
        dinf (36 B)
        stbl (60 B)
          stsd (16 B)  -- 0 sample entries
          stts (16 B)  -- 0 time-to-sample entries
          co64 (12 B)  -- MALFORMED: size=12, no entry_count field inside box
          [4 B = 0x10000000]  <-- read by constructor as entry_count (out-of-bounds)
          [4 B = 'ZZZZ']
Total: 433 bytes
```

## Fix

Add an unsigned-safe computation before the comparison:

```cpp
// Safe: avoid underflow when size < AP4_FULL_ATOM_HEADER_SIZE + 4
if (size < AP4_FULL_ATOM_HEADER_SIZE + 4) {
    m_EntryCount = 0;
} else {
    AP4_UI32 max_entries = (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 8;
    if (m_EntryCount > max_entries) m_EntryCount = max_entries;
}
```

Or equivalently, tighten the `Create()` guard:

```cpp
if (size < AP4_FULL_ATOM_HEADER_SIZE + 4) return NULL;
```

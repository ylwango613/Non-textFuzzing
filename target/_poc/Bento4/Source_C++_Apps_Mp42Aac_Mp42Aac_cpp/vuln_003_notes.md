# VULN-003: AP4_StcoAtom Integer Underflow — PoC Notes

## Vulnerability Summary

| Field         | Value |
|---------------|-------|
| File          | `Source/C++/Core/Ap4StcoAtom.cpp`, lines 77–82 |
| CWE           | CWE-191 (Integer Underflow), CWE-770 (Allocation Without Limits) |
| Trigger path  | `mp42aac` → `AP4_File` → `AP4_AtomFactory` → `AP4_StcoAtom::Create` → constructor |
| Effect        | `std::bad_alloc` crash (attempted ~4 GB heap allocation) |

## Root Cause

```cpp
// Ap4StcoAtom.cpp lines 77-82
stream.ReadUI32(m_EntryCount);
if (m_EntryCount > (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4) {
    m_EntryCount = (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4;
}
m_Entries = new AP4_UI32[m_EntryCount];
```

`AP4_FULL_ATOM_HEADER_SIZE = 12` (4 bytes size + 4 bytes type + 4 bytes version/flags).

The `Create()` guard only rejects `size < AP4_FULL_ATOM_HEADER_SIZE`, i.e. `size < 12`.
A box with `size=12` passes the check.

With `size = 12` (all values are `AP4_UI32` = unsigned 32-bit):

```
max_entry_count = (12 - 12 - 4) / 4
               = (0 - 4) / 4          ← unsigned wrap
               = 0xFFFFFFFC / 4
               = 0x3FFFFFFF
```

If the in-stream `entry_count` field equals `0x3FFFFFFF`:
- `0x3FFFFFFF > 0x3FFFFFFF` → **false** → no clamping
- `new AP4_UI32[0x3FFFFFFF]` → `0x3FFFFFFF × 4 ≈ 4 GB` → `std::bad_alloc`

## Stream Read Beyond Box Boundary

With `size=12`, the declared box is exactly:

```
Bytes 0-3:   size    = 0x0000000C
Bytes 4-7:   type    = 'stco'
Bytes 8-11:  version=0, flags=0
```

There is no room for the `entry_count` field inside the box.
However, `stream.ReadUI32(m_EntryCount)` reads the next 4 bytes unconditionally,
pulling them from **outside** the declared box boundary — the bytes belonging to
the next box (or padding) in the enclosing container.

## PoC Construction

The crafted MP4 embeds a minimal but structurally valid container hierarchy to
ensure the parser reaches the `stbl` level:

```
ftyp
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr  (soun)
      minf
        smhd
        dinf (dref/url)
        stbl
          stsd
          stts
          stsz
          stco  ← size=12 (12-byte box)
          [0x3F 0xFF 0xFF 0xFF]  ← 4 bytes read as entry_count
mdat
```

The `stco` box is crafted as a raw 12-byte sequence. The 4 bytes immediately
following it in the `stbl` payload are `0x3FFFFFFF` in big-endian. The parser
reads these as `entry_count` (outside the box boundary), then attempts the
4 GB allocation.

## Expected Behavior

| Scenario | Outcome |
|----------|---------|
| Unpatched binary | `std::bad_alloc` uncaught exception → crash / abort |
| ASAN/UBSAN build | `terminate called after throwing an instance of 'std::bad_alloc'` / SIGABRT |
| OOM-constrained env | OOM kill before exception |

## Fix

Add a size check **before** reading `entry_count`:

```cpp
if (size < AP4_FULL_ATOM_HEADER_SIZE + 4) {
    // Not enough room for entry_count field; reject the atom
    m_EntryCount = 0;
    m_Entries = nullptr;
    return;
}
```

This ensures `(size - AP4_FULL_ATOM_HEADER_SIZE - 4)` cannot underflow.

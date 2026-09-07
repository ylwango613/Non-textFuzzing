# VULN 001 PoC Notes: Integer Overflow in EnsureCapacity via Crafted elst entry_count

## Vulnerability Summary

- **File**: `Bento4/Source/C++/Core/Ap4ElstAtom.cpp` lines 72–73
- **Also**: `Bento4/Source/C++/Core/Ap4Array.h` line 172 (`EnsureCapacity`)
- **Type**: Integer overflow → huge heap allocation → DoS (std::bad_alloc) or OOB write

## Root Cause

In `AP4_ElstAtom::AP4_ElstAtom(...)` (the stream-parsing constructor):

```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);          // no bounds check
m_Entries.EnsureCapacity(entry_count); // return value IGNORED
```

`EnsureCapacity` calls `::operator new(count * sizeof(AP4_ElstEntry))`.

`sizeof(AP4_ElstEntry) = 24` (AP4_UI64 + AP4_SI64 + AP4_UI16 + 6 bytes padding).

With `entry_count = 0x20000000`:
- **32-bit build**: `0x20000000 * 24` overflows 32-bit → wraps to 0 → `new` allocates 0 bytes → OOB writes on Append.
- **64-bit build**: `0x20000000 * 24 = 0x300000000` (~12 GB) → `std::bad_alloc` thrown → crash/DoS.

## PoC Approach

Build a minimal valid MP4 file containing:
```
ftyp (16 bytes)
moov
  trak
    edts
      elst: version=0, flags=0, entry_count=0x20000000, NO actual entry data
```

The `elst` box claims 0x20000000 entries but provides zero bytes of entry data.
The parser reaches the `elst` constructor, reads `entry_count`, and immediately calls
`EnsureCapacity(0x20000000)` before any loop iteration — triggering the allocation.

## Expected Behavior (64-bit ASAN build)

- `::operator new(12884901888)` is called (~12 GB).
- ASAN intercepts and the allocation fails → `std::bad_alloc` is thrown.
- `std::bad_alloc` propagates uncaught through the call chain (no try/catch in the constructor, Create(), or AtomFactory).
- The runtime calls `std::terminate()` → SIGABRT.
- Result: process crash (DoS). ASAN/UBSAN log may report the termination.

## Trigger Path

```
main
  AP4_File constructor
    AP4_File::ParseStream
      AP4_AtomFactory::CreateAtomFromStream (moov)
        AP4_MoovAtom constructor → ReadChildren
          AP4_AtomFactory::CreateAtomFromStream (trak)
            AP4_TrakAtom constructor → ReadChildren
              AP4_AtomFactory::CreateAtomFromStream (edts)
                AP4_ContainerAtom → ReadChildren
                  AP4_AtomFactory::CreateAtomFromStream (elst)
                    AP4_ElstAtom::Create → AP4_ElstAtom constructor
                      EnsureCapacity(0x20000000)   ← VULNERABILITY
                        ::operator new(~12 GB)     ← std::bad_alloc / crash
```

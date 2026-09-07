# VULN 001 – AP4_NullTerminatedStringAtom Heap OOB Write

## Vulnerability Summary

**CWE**: CWE-787 (Out-of-bounds Write)  
**File**: Ap4Atom.cpp, lines 466-476  
**Binary**: mp42aac (Bento4)

## Root Cause

`AP4_NullTerminatedStringAtom` computes the string payload size as:

```cpp
AP4_Size str_size = (AP4_Size)size - AP4_ATOM_HEADER_SIZE;  // line 471
```

`AP4_Size` is `AP4_UI32` (unsigned 32-bit). `AP4_ATOM_HEADER_SIZE` is 8. When the
atom's `size` field in the file equals 8 (header only, no data payload):

```
str_size = 8 - 8 = 0
```

A zero-length heap buffer is then allocated:

```cpp
AP4_Byte* str = new AP4_Byte[str_size];   // new AP4_Byte[0]
```

Immediately after, the code null-terminates the string:

```cpp
str[str_size - 1] = '\0';   // str[0xFFFFFFFF] = '\0'  -- WRAP-AROUND
```

Because `str_size` is unsigned and equals 0, `str_size - 1` wraps to `0xFFFFFFFF`
(4,294,967,295). The write goes ~4 GB past the start of the heap allocation —
a classic heap out-of-bounds write.

## Trigger Condition

The type code that exercises this path is `8id ` (bytes `0x38 0x69 0x64 0x20`),
handled by `AP4_DefaultAtomFactory` which dispatches to
`AP4_NullTerminatedStringAtom`.

An 8-byte atom box with this type (size=8, no payload) embedded inside a `moov`
container is sufficient to trigger the bug when fed to `mp42aac`.

## PoC Approach

1. `vuln_001_gen.py` builds a minimal but structurally valid MP4:
   - `ftyp` box (parser entry point)
   - `moov` box containing:
     - a minimal `mvhd` box (required metadata)
     - the malicious `8id ` atom (8 bytes total: 4-byte size + 4-byte type, zero payload)
2. `mp42aac` parses the file, reaches the `8id ` atom, instantiates
   `AP4_NullTerminatedStringAtom`, and triggers the OOB write.

## Expected ASAN Output

With an ASAN+UBSAN build, the crash manifests as:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1 at 0x... shadow bytes around the buggy address ...
```

The write offset will be 0xFFFFFFFF bytes past the base of the 0-byte allocation.

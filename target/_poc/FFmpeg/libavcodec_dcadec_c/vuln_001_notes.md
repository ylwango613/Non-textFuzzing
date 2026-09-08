# VULN 001 – OOB Read on dca2wav[] in FFmpeg DCA Decoder

## Vulnerability Summary

- **CWE**: CWE-125 (Out-of-Bounds Read)
- **File**: `libavcodec/dcadec.c`
- **Functions**: `ff_dca_set_channel_layout()` (primary trigger), `ff_dca_export_downmix_matrix()` (secondary)
- **Root cause**: `dca2wav_norm[]` and `dca2wav_wide[]` have 28 elements (indices 0–27), but the
  code can iterate up to `DCA_SPEAKER_COUNT = 32` or `av_log2(output_mask)` when high-numbered
  speaker bits are present in `dca_mask` / `output_mask`.

## Trigger Conditions

1. A DCA CSS (core) frame with `audio_mode = 9` (3F2R, five channels).
2. A XXCH channel-set extension embedded after the core audio, carrying
   `xxch_mask_nbits = 32` and a loudspeaker layout mask that sets bit 31 of
   `xxch_spkr_mask` (speaker `RSV4`, enum index 31).
3. `prim_dmix_embedded = 1` in the REV1AUX auxiliary data block (needed for
   `ff_dca_export_downmix_matrix` path; also ensures the relevant decode path
   executes).
4. FFmpeg invoked with `-channel_order coded` to route through
   `ff_dca_set_channel_layout()`'s loop over `DCA_SPEAKER_COUNT` entries.

## Crafted File Structure (128 bytes)

| Byte range | Content |
|---|---|
| 0–3   | DCA sync word `0x7FFE8001` |
| 4–12  | Frame header: `audio_mode=9`, `aux_present=1`, `ext_audio_type=6` (XXCH), `ext_audio_present=1` |
| 13–41 | Audio coding header: 5 channels, `scale_factor_sel=5`, `bit_allocation_sel=5`, quant_index_sel all-max |
| 42–56 | Subframe: 1 sub-sub-frame, silent samples (abits=0), VQ index=0 |
| 57–59 | Aux preamble: 6-bit byte-count + alignment padding |
| 60–63 | REV1AUX sync word `0x9A1105A0` |
| 64–77 | Aux data: `prim_dmix_embedded=1`, `prim_dmix_type=1` (LoRo), 10 × zero coefficients, CRC=0 |
| 78–79 | Padding |
| 80–83 | XXCH sync word `0x47004A03` |
| 84–93 | XXCH frame header: `header_size=14`, `xxch_mask_nbits=32`, 1 channel set, `xxch_frame_size=16`, `xxch_core_mask=0x1F` |
| 94–109 | XXCH channel set: `xxch_spkr_mask=0x80000000` (bit 31), 1 silent channel |
| 110–127 | Zero padding |

## Parsing Flow

1. `ff_dca_core_parse()` decodes the core frame header, audio coding header, and
   subframe data.
2. `parse_optional_info()` / `parse_aux_data()` finds the REV1AUX block at byte 60,
   sets `s->prim_dmix_embedded = 1`.
3. `parse_optional_info()` searches backward for the XXCH sync word at 4-byte
   boundaries; finds `0x47004A03` at byte 80 (4-word position 20), sets `s->xxch_pos = 640`.
4. `ff_dca_core_parse_exss()` → `parse_xxch_frame()`:
   - Reads `xxch_mask_nbits = 32`, `xxch_frame_size = 16`, `xxch_core_mask = 0x1F`.
   - Validates `xxch_core_mask == s->ch_mask` (both 0x1F for 3F2R). ✓
   - Calls `parse_coding_header(HEADER_XXCH, xch_base=5)`:
     - Reads 26-bit mask field = `(1<<25)`, shifts left by `DCA_SPEAKER_Cs=6`:
       `xxch_spkr_mask = (1<<25) << 6 = (1<<31) = 0x80000000`.
     - `av_popcount(0x80000000) = 1 = nchannels`. ✓
     - `0x1F & 0x80000000 = 0` (no collision). ✓
     - `s->ch_mask = 0x1F | 0x80000000 = 0x8000001F`.
   - Sets `s->ext_audio_mask |= DCA_CSS_XXCH`.
5. `ff_dca_core_filter_frame()` → `ff_dca_set_channel_layout(..., 0x8000001F)`:
   - With `-channel_order coded`: iterates `dca_ch` from 0 to `DCA_SPEAKER_COUNT-1 = 31`.
   - At `dca_ch = 31`: `0x8000001F & (1<<31)` is true → accesses `dca2wav[31]`.
   - **`dca2wav` has only 28 elements (indices 0–27)**: `dca2wav[31]` is out-of-bounds.

## Note on ff_dca_export_downmix_matrix Path

The call to `ff_dca_export_downmix_matrix()` in `ff_dca_core_filter_frame()` is
guarded by:
```c
!(s->ext_audio_mask & (DCA_CSS_XXCH | DCA_CSS_XCH | DCA_EXSS_XXCH))
```
Since XXCH parsing sets `ext_audio_mask |= DCA_CSS_XXCH`, this guard blocks that
call.  The **active OOB path** is therefore `ff_dca_set_channel_layout()` when
`-channel_order coded` is used.

## CRC Notes

`ff_dca_check_crc()` returns 0 immediately unless `avctx->err_recognition` has
`AV_EF_CRCCHECK` or `AV_EF_CAREFUL` set (neither is the default).  All CRC
fields in the generated file are therefore set to zero.

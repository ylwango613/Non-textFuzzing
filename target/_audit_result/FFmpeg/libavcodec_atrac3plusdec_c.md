After an exhaustive multi-pass review of `atrac3plusdec.c` and all called functions/data tables across `atrac3plus.c`, `atrac3plusdsp.c`, `atrac3plus.h`, and `atrac3plus_data.h`, I verified the following:

**Group 1 – Main decoder (`atrac3plusdec.c`)**
- `channel_map[out_ch_index + i]` always stays in bounds because `ch_block >= ctx->num_channel_blocks` check enforces that the total channels processed matches the init-time configuration.
- `samples_p[channel_map[...]]` values stay ≤ `nb_channels - 1` by design of `channel_map[8][8]`.
- `ctx->ch_units[ch_block]` allocation via `av_calloc(num_channel_blocks, sizeof(*ch_units))` is safe.

**Group 2 – Bitstream parser (`atrac3plus.c`)**
- `qu_wordlen[32]`, `qu_sf_idx[32]`, `qu_tab_idx[32]` only accessed up to `num_quant_units - 1` ≤ 31.
- `num_quant_units` rejects values 29-31 but allows 32; `atrac3p_qu_to_subband[31]` is valid (array has 32 entries).
- `decode_gainc_npoints` VLC (gain_vlc_tabs[0]) xlat values are 0-7, bounded to `AtracGainInfo.lev_code[7]` / `loc_code[7]`.
- `num_long_vals = get_bits(gb, 5)` without validation in `weight_idx == 3` branch: max index 30 < 32 — within `qu_sf_idx[32]`.
- `atrac3p_sf_shapes[64][9]` indexed by `get_bits(gb, 6)` (0-63) is safe; `atrac3p_qu_num_to_seg[i]-1` for `i≥3` gives values 0-8, within 9-element shape vector.
- `tones_index + num_wavs > 48` guard keeps all `waves[48]` accesses in bounds.
- `num_tone_bands` VLC gives 1-16 = ATRAC3P_SUBBANDS; `band_has_tones[16]` stays in bounds.
- `loc_code` values validated post-decode against `> 31`.

**Group 3 – DSP (`atrac3plusdsp.c`)**
- `subband_to_powgrp[sb]` (values 0-4) indexes `power_levs[5]` correctly.
- `power_levs[i] = get_bits(gb,4)` (0-15) indexes `pwc_levs[16]` correctly.
- `decode_qu_spectra`: `group_size * num_coeffs` (max 16) always divides all `num_specs` values (16, 32, 64, 128) — no overshoot OOB write.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

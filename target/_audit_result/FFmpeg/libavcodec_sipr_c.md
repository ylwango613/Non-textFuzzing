After reading all sections of `sipr.c` and `sipr16k.c` and cross-referencing headers, I have completed the analysis. Here is the full audit trace:

**Group 1 (sipr.c lines 1–215):** `sipr_decoder_init`, `decode_parameters`, `sipr_decode_frame`. The packet size check `avpkt->size < (bits_per_frame >> 3)` is exact for all four modes (all `bits_per_frame` values are divisible by 8). Mode selection is bounded to the valid enum. `decode_parameters` accesses `fc_indexes[5][10]` with `i < subframe_count ≤ 5` and `j < number_of_fc_indexes ≤ 10` — within bounds.

**Group 2 (sipr.c lines 216–479):** `decode_frame`. The excitation buffer is `float[L_INTERPOL + PITCH_MAX + 2*L_SUBFR_16k] = float[452]`. Working pointer starts at `ctx->excitation + PITCH_DELAY_MAX + L_INTERPOL = ctx->excitation + 154`. Max forward write for MODE_5k0 (5 subframes × 48): offset 394 < 452. `synth_buf[256]` is accessed via `synth = synth_buf + 16`; MODE_5k0 writes through `synth[239] = synth_buf[255]` — exactly on boundary, no overflow. `postfilter_syn5k0[250]` is written at max offset `10 + 4×48 = 202`, plus 48 = 250 — exactly on boundary.

**Group 3 (sipr.c codebooks in siprdata.h):** `gain_cb[128][2]` with `gc_index_bits=7` (0–127) ✓; `lsf_cb1[64]` with 6-bit index ✓; `lsf_cb2/3/4[128]` with 7-bit indices ✓; `lsf_cb5[32]` with 5-bit index ✓. `AMRFixed.x[10]/y[10]` — all three modes set `n ≤ 6` with indices within bounds.

**Group 4 (sipr16k.c):** `excitation = ctx->excitation + 292` = `L_INTERPOL + PITCH_MAX`. Pitch delay max for 9-bit field: 281 = PITCH_MAX. Minimum lookback: `excitation[0] − 281 + 1 = ctx->excitation + 12` — within bounds. `lsf_cb2_16k[256]` with 8-bit index ✓; `qu[2]` with `ma_pred_switch ∈ {0,1}` ✓; `gain_cb_16k[32]` with 5-bit index ✓; `gain_pitch_cb_16k[16]` with 4-bit index ✓. Pulse positions via `ff_fc_4pulses_8bits_tracks_13` are 0,5,10…75 + track offset 0–4 = max 79 < L_SUBFR_16k=80 ✓.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

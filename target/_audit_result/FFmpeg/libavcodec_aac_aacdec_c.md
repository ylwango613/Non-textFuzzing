After reading all 2702 lines of aacdec.c in five passes, and tracing every allocation, array index, and bounds check through related headers and tables, here is my final conclusion:

**Summary of all bounds verified:**
- `band_type[128]` / `sfo[128]` / `ms_mask[128]` — indexed via `g*max_sfb + k`; enforced by `if (max_sfb > num_swb) → fail` in `decode_ics_info`. Maximums: EIGHT_SHORT (8×15=120<128), LONG (1×51=51<128). ✓
- `group_len[8]` — `num_window_groups` starts at 1, increments max 7 more times → max 8. ✓
- `TemporalNoiseShaping.n_filt[8]` — `num_windows` ≤ 8; `n_filt[w] ≤ 3` for long, `≤ 1` for short; `order[w][filt] ≤ tns_max_order ≤ 20 = TNS_MAX_ORDER`. ✓
- `ff_tns_tmp2_map[tmp2_idx][bits]` — `tmp2_idx` ∈ {0-3}; index values match table sizes (4, 8, or 16 entries). ✓
- `DynamicRangeControl.band_top[17]` / `dyn_rng_sgn[17]` / `dyn_rng_ctl[17]` — `drc_num_bands = 1 + band_incr ≤ 16`. ✓
- `DynamicRangeControl.exclude_mask[64]` — loop terminates when `num_excl_chan = 63 < 64`. ✓
- `height_map[4][16]` / `tag[6][16][3]` in PCE height extension — enum values 1-5, second dimension ≤ 15 (4-bit field). ✓
- `layout_map[256][3]` writes — max tags = 15+15+15+3+15 = 63; `id_map[7][64]` accessed only with validated type ∈ {0-3}. ✓
- LATM `mux_slot_length` potential integer overflow — caught by `< 0` check; value never used to bound memory access. ✓
- `buf[256]` in `decode_fill` — loop condition `i+1 < 256` limits max write to `buf[255]`. ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

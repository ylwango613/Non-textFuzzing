Based on my complete analysis of `aacdec_usac_mps212.c` and its call chain, let me verify the last potential concern — the `extend_frame` indexing in `ff_aac_map_index_data`.

Key findings:
- `MPS_MAX_PARAM_SETS = 9`, `MPS_MAX_PARAM_BANDS = 28`
- `nb_param_sets` is bounded by `get_bits(gb, 3) + 1` → max 8 (never 9), so `dst_idx[nb_param_sets]` at line 913 can only reach index 8, which is valid for a 9-element array
- `lav` from `ff_aac_lav_tab_XXX` is always ∈ {3,5,7,9} for CLD, {1,3,5,7} for ICC/IPD — all handled by the switch → `hcod2D` is always initialized
- `freq_res = 0` (which would give `nb_bands = 255` and overflow `freq_stride_map[29]`) is explicitly rejected at config parse time with `if (!e->mps.freq_res) return AVERROR_INVALIDDATA`
- `esc_idx[28]` and `esc_data[2][28]`: maximum `esc_cnt = 28` writes indices 0..27, staying within bounds
- All `memcpy` calls are size-bounded by `nb_bands ≤ 28` and `start_band = 0`, keeping all copies in-bounds

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

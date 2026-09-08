Based on my thorough multi-batch analysis of all 1596 lines of `av1dec.c` plus the relevant CBS layer, CBS AV1 template, and header files, here is a summary of what I checked and found:

**Batch 1 (lines 1–500):** Examined `init_tile_data` (multiplication `tile_cols * tile_rows` is bounded to 64×64=4096 by CBS constraints), `get_tiles_info` (array index `tile_num` bounded by CBS-validated `tg_end < num_tiles`), `resolve_divisor` (div_lut index `f` stays in [0,255] since input `d = abs(param[2]) > 0` with `av_log2 ≤ 30`).

**Batch 2 (lines 500–1000):** Examined pixel format dispatch, `av1_frame_alloc`, `export_film_grain` (CBS limits `num_y_points ≤ 14`, `num_cb/cr_points ≤ 10`, matching the target array sizes). No unsafe array accesses.

**Batch 3 (lines 1000–1596):** Examined `export_metadata`, `av1_receive_frame_internal` (`frame_to_show_map_idx` is 3-bit → 0–7; `s->ref` has 8 slots), `load_grain_params` (`film_grain_params_ref_idx` is 3-bit → 0–7), `read_global_param` (`primary_ref_frame` 3-bit 0–6 → `ref_frame_idx[0..6]` → 3-bit 0–7 into 8-slot `s->ref`), `skip_mode_params` (first loop null-checks all `raw_frame_header` before second loop).

**CBS validation confirmation:** `cbs_av1_read_unsigned` enforces hard range limits and returns `AVERROR_INVALIDDATA` for out-of-range values. Fields `tg_start`/`tg_end` are clamped to `[tile_num_prev, num_tiles-1]`. The tile array is always allocated to `num_tiles = tile_cols × tile_rows` entries. All 3-bit ref index fields stay 0–7, matching the 8-entry `s->ref[]` array.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

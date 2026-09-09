After comprehensive analysis of all the files included by `dsp_template.c` — reading every function, tracing buffer sizes against the maximum allowable dimensions, and following the full data flow from bitstream input to DSP operations — the following was verified:

1. **`apply_bdof`** (`inter_template.c:442-468`): Stack arrays `gradient_h[2][BDOF_BLOCK_SIZE*BDOF_BLOCK_SIZE]` (256 elements each). Maximum index 255 is safe because `refine_regular_subblock` (`ctu.c:1769-1770`) enforces `num_sb_x = cb_width >> 4` for cb_width > 16, bounding all BDOF sub-blocks to exactly 16×16.

2. **`put_scaled`** (`inter_template.c:26-81`): `tmp_array[TMP_STRIDE * MAX_PB_SIZE]` = 163,840 elements. `src_height` is computed by `emulated_edge_scaled` as `≤ MAX_SCALING_RATIO * MAX_PB_SIZE = 8 * 128 = 1024`; with `LUMA_EXTRA = 7`, max column usage is 1031 ≪ TMP_STRIDE = 1280. Max total index with `width = 128`: `127 × 1280 + 1030 = 163,590 < 163,840`. ✓

3. **`prof_grad_filter`** / **`apply_bdof_min_block`** (`inter_template.c:294-438`): All gradient array indices proven bounded at 255 for the 16×16 BDOF block constraint.

4. **ALF buffers** (`filter_template.c`): `gradient_tmp[66×66×4 = 17,424]` — maximum access at index 17,423. `alf_recon_coeff_and_clip` accesses `clip_idx_set[class_idx * 12]` with `class_idx ≤ 24`, max offset 288 within arrays of 300 entries.

5. **`sao_band_filter`** (`h2656_sao_template.c:23-45`): `(k + sao_left_class) & 31` always in `[0..31]` for the 32-entry `offset_table`. ✓

6. **`h2656_inter_template.c`**: `put_luma_hv` buffer `tmp_array[(MAX_PB_SIZE + LUMA_EXTRA) * MAX_PB_SIZE]` = 17,280 elements, max write index 17,279. ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

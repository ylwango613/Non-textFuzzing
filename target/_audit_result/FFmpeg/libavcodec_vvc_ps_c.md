After reading all 1495 lines across four batches and cross-referencing CBS validation in `cbs_h266_syntax_template.c`, `cbs_h266.h`, `vvc.h`, and `ps.h`, here is the summary of every major area checked:

**Batch 1 (lines 1–500):**
- `sps_chroma_qp_table`: `qp_in[j+1]` writes max to index 87 < `VVC_MAX_POINTS_IN_QP_TABLE=111`; `chroma_qp_table[i][k]` max index = 63+24=87 < 111. Safe.
- `pps_bd`: CBS guarantees `sum(col_width_val)==ctb_width`, so the inner loop filling `ctb_to_col_bd[k]` stays in `[0, ctb_width-1]`. Safe.
- `subpic_tiles` while-loops: sentinel `col_bd[num_tile_columns]=ctb_width` stops each loop; CBS bounds `subpic coords ≤ ctb_width`. Safe.

**Batch 2 (lines 500–1000):**
- `pps_one_tile_slices`: local `i` bounded by CBS-validated total slice count ≤ `VVC_MAX_SLICES=1000`. `slice_height_in_ctus[i]` access always < 1000. Safe.
- `pps_rect_slice`: `tile_in_slice[tile_idx]` with CBS-bounded `tile_idx < VVC_MAX_TILES_PER_AU=990`. Safe.
- `pps_add_ctus`: bounds check `*off >= pps->ctb_count` prevents OOB writes. Safe.
- `lmcs_derive_lut`: `idx_y = sample >> shift ≤ 15 < LMCS_MAX_BIN_SIZE=16`; pivot/lut arrays sized correctly. Safe.
- `ph_vb_pos`: `num_pos ≤ VVC_MAX_VBS=3`, array `vb_pos_x/y` has 3 elements. Safe.

**Batch 3 (lines 1000–1495):**
- `sh_slice_address` formula `row_bd[ty]*ctb_width + col_bd[tx]*row_height_val[ty]` is the correct tile raster-scan offset, bounded ≤ `ctb_count−1`. Safe.
- `sh_entry_points` / `j` overflow into `entry_point_start_ctu[VVC_MAX_ENTRY_POINTS=4050]`: CBS independently validates and rejects any bitstream with `num_entry_points > 4050` before `sh_derive` is ever called. Safe.
- `scaling_derive`: CBS bounds `scaling_list_pred_id_delta` so `ref_id = id − delta ≥ 0`; all `scaling_matrix_rec[ref_id]` accesses valid. Safe.
- ALF/LMCS/scaling-list APS IDs: all 2–3-bit CBS-constrained fields, arrays sized accordingly. Safe.
- `sh_alf_aps`: IDs are 3-bit values (0–7), `alf_list[8]` sized correctly. Safe.

**Data-type note:** `pps->slice_start_offset` and `pps->num_ctus_in_slice` are `uint16_t` but conceptually hold values up to `ctb_count` (≤627264 for 32-CTU 25332×25332). Wrapping is a correctness/logic issue but not a memory-safety issue: the truncated offset is always ≤65535 ≤ ctb_count (so pointer arithmetic stays within the heap allocation), and a wrapped zero count is rejected by the `!num_ctus_in_curr_slice` guard at line 1366.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

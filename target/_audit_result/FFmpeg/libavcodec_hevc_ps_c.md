I've read all 2506 lines of `ps.c` in five batches (lines 0–500, 500–1000, 1000–1500, 1500–2000, 2000–2506) and cross-referenced `ps.h`, `hevc.h`, and all key constants. Below are the per-batch findings before the final verdict.

---

**Batch 1 (0–500): VPS/SPS short-term RPS, PTL parsing**

- `ff_hevc_decode_short_term_rps` predict path: loop `i = 0; i <= rps_ridx->num_delta_pocs` writes `used[k]` and `delta_poc[k]` at the *current* k, then increments k. The post-loop check `k >= FF_ARRAY_ELEMS(used)` (32) is correct: the max k at write time is 31 (last valid index). No OOB.
- `rps->used |= get_bits1(gb) * (1 << (rps->num_negative_pics + i))` — max shift is `1 << 30` into `uint32_t`. Fine.
- `dimension_id_len[16]`: max `num_scalability_types` = 16 via popcount of 16-bit mask. Array is exactly 16. No OOB.

**Batch 2 (500–1000): VPS extension, HRD, VUI**

- `decode_sublayer_hrd`: `nb_cpb` = cpb_cnt_minus1+1 ≤ 32. Arrays in `HEVCSublayerHdrParams` are `HEVC_MAX_CPB_CNT = 32`. No OOB.
- `dimension_id_len[num_scalability_types-1] = 5 - n` can wrap to a large `uint8_t` when splitting_flag=1 and n>5. However this wrapped value is only read inside `if (!splitting_flag)`, which is skipped in that branch. Not exploitable.
- `skip_bits_long(gb, (vps_num_layer_sets-2)*(vps_max_layer_id+1))` max = 1022×64 = 65408 bits. Fits in `int`. Fine.

**Batch 3 (1000–1500): VUI decode, scaling list, SPS parse**

- `av_image_check_size` enforces `w*h ≤ INT_MAX` before CTB dimension math. No integer overflow in ctb_width/ctb_height product.
- Scaling list: arrays `sl[4][6][64]`; accesses bounded by loop limits and explicit checks. No OOB.
- SPS palette: `sps_num_palette_predictor_initializers` checked `> HEVC_MAX_PALETTE_PREDICTOR_SIZE (128)`. Array is `[3][128]`. Fine.

**Batch 4 (1500–2000): SPS tail, PPS start, multilayer ext**

- `setup_pps` tile BD arrays: `col_bd[num_tile_columns+1]`, `row_bd[num_tile_rows+1]`. Accesses `col_bd[i+1]` with i < num_tile_columns. Fine.
- `pps_multilayer_extension`: `ref_loc_offset_layer_id[i]` is 6 bits (0–63), used to index `scaled_ref_layer_*[64]`. Size 64. Fine.
- `pps_3d_extension` → `delta_dlt`: `num_val_delta_dlt` can be huge (up to 2^23-1), causing DoS via tight loop, but no memory corruption.

**Batch 5 (2000–2506): setup_pps tiling, tile_id, min_tb_addr_zs**

- `ctb_addr_ts_to_rs[val]`: `val` is the tile-scan bijection on `[0, pic_area_in_ctbs-1]`. Array size equals `pic_area_in_ctbs`. No OOB.
- `ctb_addr_rs_to_ts[y*ctb_width+x]`: y < ctb_height, x < ctb_width; product < pic_area_in_ctbs. Fine.
- `min_tb_addr_zs_tab[(tb_mask+2)*(tb_mask+2)]`: tb_mask ≤ 15 (log2_diff ≤ 4, enforced by log2_ctb_size ≤ 6 and log2_min_tb_size ≥ 2). Array size 17×17 = 289. No OOB.
- `tile_pos_rs[j*num_tile_columns+i]`: j < num_tile_rows, i < num_tile_columns; bounded by allocated tile_id entries. Fine.

---

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

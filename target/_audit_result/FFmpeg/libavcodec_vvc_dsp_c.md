After a thorough multi-pass read of `dsp.c` (120 lines) and all three template files it includes (`dsp_template.c`, `inter_template.c`, `intra_template.c`, `filter_template.c`), plus tracing key callers in `inter.c`, `ctu.c`, and `cabac.c`, here is the complete picture of every suspicious pattern examined:

**BDOF gradient buffers** (`apply_bdof`): `gradient_h[2][BDOF_BLOCK_SIZE*BDOF_BLOCK_SIZE]` — 256 elements each. When `block_w = block_h = 16`, the worst-case index inside `derive_bdof_vx_vy` is exactly 255 because `pad_right/pad_bottom` clamp the dy/dx to ≤3 at the edges. Confirmed in-bounds.

**`put_scaled` tmp_array**: `int16_t tmp_array[TMP_STRIDE * MAX_PB_SIZE]` = `1280 × 128` = 163840 elements. Width is capped at `MAX_PB_SIZE = 128` by the VVC CU size constraint, and `src_height + extra ≤ ~1031 < TMP_STRIDE = 1280`. Confirmed in-bounds.

**`dmvr_hv` ping-pong buffers**: `int16_t tmp_array[MAX_PB_SIZE * 2]`. The DMVR sub-block size is enforced by `num_sb_x/y` to ≤16, so `pred_w = block_w + 4 ≤ 20 << 128`. Confirmed in-bounds.

**Angular intra prediction** (`prepare_intra_edge_params`, ref_idx = 3 code path): The code contains `ref_idx == 3 ? -4 : (-1 - ref_idx)` — with `ref_idx = 3` and `h = 64`, `p[-64]` would underflow `top_array`. However, `ff_vvc_intra_luma_ref_idx` CABAC-decodes only 0, 1, or 2 (two context-coded bits) from the bitstream; value 3 is unreachable from any compliant or malformed VVC stream.

**Stack arrays in `IntraEdgeParams`**: `uint16_t left_array[6*MAX_TB_SIZE+5]` = 389 elements. Pointers start at offset 67; worst-case write index 194 (for `left_size = 128`). Confirmed in-bounds.

**`lmcs_filter_luma` LUT indexing**: `lut[dst[x]]` — `dst[x]` is a valid pixel ∈ [0, 2^BIT_DEPTH−1] and the LUT covers that full range. Safe.

**`alf_recon_coeff_and_clip` class_idx**: Bounded to [0, 24] by `alf_get_idx`; `class_to_filt`, `coeff_set`, and `clip_idx_set` are sized accordingly by the VVC spec. Safe.

**`vvc_sad` pointer arithmetic**: `dx, dy` come from a 5×5 search grid [0,4], post-subtraction they are [−2,2]; offsets into `lc->pred.tmp` stay within the `pred_h × MAX_PB_SIZE` allocation. Safe.

No allocation calls (`av_malloc`, `av_realloc`) appear in any of these files — all buffers are stack-allocated with compile-time sizes matched to algorithm requirements. After exhaustively tracing every buffer access against its allocation and the achievable input ranges from the CABAC-controlled decode path, no externally-triggerable memory-safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

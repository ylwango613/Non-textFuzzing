After a thorough multi-pass analysis of the entire file (634 lines), all related headers, calling contexts, and data tables, I have verified:

**Group 1 (lines 1–82, `put_scaled`)**: `tmp_array[TMP_STRIDE * MAX_PB_SIZE]` is 163,840 int16_t elements — large enough for any VVC block (width ≤ 128). The `LUMA_FILTER(src, 1)` uses the `x` variable that IS in scope from the outer loop (it's not dead — the macro expansion uses `src[x ± k]`). Border accesses are covered by `emulated_edge_scaled` with `LUMA_EXTRA_BEFORE/AFTER` padding. No OOB.

**Group 2 (lines 260–287, `bdof_fetch_samples`)**: `_dst - 1 - MAX_PB_SIZE` lands at `lc->pred.tmp[31]` (PROF_TEMP_OFFSET=160 − 129 = 31). All writes stay within `lc->pred.tmp[16384]`. No OOB.

**Group 3 (lines 295–332, `prof_grad_filter` + `apply_bdof`)**: `gradient_h/v[2][256]` — BDOF blocks are always subdivided to exactly 16×16 by `refine_regular_subblock` (line 1769–1770 in ctu.c: `num_sb_x = cb_width >> 4` for cb_width > 16, making sbw = 16). `prof_grad_filter` with width=16, height=16, stride=16 fills exactly 256 elements. All `derive_bdof_vx_vy` accesses with padding clamps stay within gradient_h[0][0..255]. No OOB.

**Group 4 (lines 391–421, `derive_bdof_vx_vy`)**: Negative-index accesses (`dy=-1`, `dx=-1`) are clamped by `pad_top/pad_left` for boundary subblocks, and for interior subblocks the `idx_base` offset (e.g., 64 for y=4) is large enough to absorb the −17 minimum offset. All indices in [47..255]. No OOB.

**Group 5 (lines 238–257, `put_gpm`)**: `gpm_partition_idx` is a 6-bit fixed-length decode → [0..63], exactly matching the 64-entry table. `w = av_log2(cb_width) - 3` is always [0..3] since GPM requires `!is_128` (line 1461 in ctu.c), bounding cb_width ≤ 64. `off_x` max at w=3 is 48; with width=64 and mirror step=-1, minimum index = off_y·112 + 111 − 48 − 63 = off_y·112 + 0 (exactly the row start). No OOB.

**Group 6 (lines 478–573, DMVR functions)**: `tmp_array[MAX_PB_SIZE * 2]` serves `dmvr_hv` correctly. `FFSWAP` alternates pointers within the allocated two-half buffer. `src[x + 1]` covered by BILINEAR_EXTRA_AFTER=1 padding. No OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

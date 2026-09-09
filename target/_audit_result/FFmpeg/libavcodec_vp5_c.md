After reading the full file (318 lines), all related headers (`vp56.h`, `vp56data.h`, `vp5data.h`, `vpx_rac.h`), data tables (`vp56data.c`), and the decode frame/size-change logic in `vp56.c`, here is the analysis result:

**Group 1 — vp5_parse_header (lines 38–86)**
`rows`/`cols` from `vp56_rac_gets(c,8)` (0–255), null-checked, then used in `ff_set_dimensions(s->avctx, 16*cols, 16*rows)` — max 4080 × 4080, no overflow. `render_x`/`render_y` validated against cols/rows. Clean.

**Group 2 — vp5_parse_coeff (lines 182–264)**
- `permute = s->idct_scantable` — initialized as `TRANSPOSE(ff_zigzag_direct[i])` where TRANSPOSE maps 0–63 → 0–63; `block_coeff[6][64]` access `[b][permute[coeff_idx]]` is safe.
- `ff_vp56_b6to4[] = {0,0,1,1,2,3}` — indices into `coeff_ctx[4][64]` and `coeff_ctx_last[4]` all within bounds.
- `ctx = 6*coeff_ctx[...][0] + not_null_dc` — max 6×5+5=35, within `coeff_dcct[2][36][5]`.
- `cg = vp5_coeff_groups[coeff_idx]` — only accessed at coeff_idx 1–63 (entry 0 = 255 never reached), values 0–5, within `coeff_ract[2][3][6][11]`.
- `coeff_acct[pt][ct][cg][ctx]` — only when `cg≤2` and `ctx≤5`, within `[2][3][3][6][5]`. Safe.
- `ff_vp56_pc_tree` leaf nodes return 0–5; `ff_vp56_coeff_bias[idx+5]` (idx+5∈5–10, array len 11) and `ff_vp56_coeff_parse_table[idx][i]` (idx∈0–5, i∈0–10, array `[6][11]`) are safe.
- `ctx_last` capped at 24 by `FFMIN`; loop indices within `coeff_ctx[4][64]`. Clean.

**Group 3 — vp5_parse_coeff_models (lines 135–180)**
All `pt/ct/cg/ctx/node` loop variables match array declarations in `VP56Model`. Clean.

**Group 4 — vp5_parse_vector_models / vp5_parse_vector_adjustment**
`comp∈{0,1}`, `node∈0..6`, `vp5_vmc_pct[2][11]` — all in bounds. Clean.

**Group 5 — vp56_size_changed**
`mb_width/mb_height` guarded by ≤1000; `av_reallocp_array` checked for overflow internally; `above_block_idx` maximum value `4*mb_width+4` stays within allocated `4*mb_width+6`. Clean.

**Group 6 — VPXRangeCoder**
`vpx_rac_renorm` checks `c->buffer < c->end` before reading; `end_reached` counter prevents unbounded reads past buffer end. No OOB read from crafted streams.

After exhaustive analysis of all array accesses, integer arithmetic, and data flows from the range coder into model/coefficient arrays and frame buffers, no exploitable memory safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

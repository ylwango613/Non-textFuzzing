After reading the complete 945-line file in two passes and exhaustively tracing all array index computations, allocation sizes, and call-site arguments, here is my analysis:

**Group 1 (lines 35–207): Scale functions** — `ff_vc1_field_mvpred_scales[table_index][...][refdist]` where `table_index = dir^second_field ∈ {0,1}` (array dim 2 ✓) and `refdist` is clamped to 0–3 (array dim 4 ✓). `brfd = FFMIN(v->brfd, 3)` (✓). No OOB possible.

**Group 2 (lines 211–464): `ff_vc1_pred_mv`** — `s->mv[2][4][2]`: `n` comes from callers always as 0–3. Negative predictor indices (e.g., `xy - wrap + off`) land within pre-offset region of `v->mb_type` (allocated `b8_stride*(2*mb_height+1)+...` with `v->mb_type = base + b8_stride + 1`) and `v->mv_f[dir]` (similar pre-offset). The `off = 2*mb_width - wrap - 1 = -2` path (when `res_rtm_flag=0`) is validated: the most negative index is `2*mb_width - 3` relative to `v->mb_type`, well inside the `-(b8_stride+1)` limit. `motion_val` duplication at lines 455–462 stays within `b8_array_size + 3`. `r_x` is at most 4096, so `r_x << 1` cannot overflow.

**Group 3 (lines 468–688): `ff_vc1_pred_mv_intfr`** — `s->mv[dir][n+1]` at lines 685–686 only executes when `mvn == 2`; all call sites pass n∈{0,2} for mvn=2 (line 1624: n=0; line 1631: n=2; line 2342: j=i>1?2:0 → 0 or 2). `n+1 ≤ 3` always. `s->block_index[n_adj]` with n_adj ∈ {0,1,2,3} (verified at lines 533,536,551,565). `v->luma_mv[s->mb_x]` bounded by `luma_mv_base` allocation of `3*mb_stride`.

**Group 4 (lines 690–887): `ff_vc1_pred_b_mv`** — `motion_val[0][xy-2]` write at line 744 gated by `!s->mb_x`. All other accesses bounded.

**Group 5 (lines 889–945): `ff_vc1_pred_b_mv_intfi`** — `n` passed to `ff_vc1_pred_mv` as 0–3 from callers (vc1_block.c:2109 loop i<4).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

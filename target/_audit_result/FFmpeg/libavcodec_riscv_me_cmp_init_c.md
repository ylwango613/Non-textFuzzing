The file is 113 lines. I've read it completely. Let me verify the `MECmpContext` array bounds against every index used in the init function.

From `me_cmp.h` (line 50-70):
- `sad[6]`, `sse[6]`, `vsad[6]`, `vsse[6]`, `nsse[6]` — all size 6 (valid indices 0–5)
- `pix_abs[2][4]` — valid indices [0–1][0–3]

From `me_cmp_init.c` (lines 86–109), all accesses:
- `sad[0]`, `sad[1]` — within [0..5] ✓
- `sse[0]`, `sse[1]`, `sse[2]` — within [0..5] ✓
- `vsse[0]`, `vsse[1]`, `vsse[4]`, `vsse[5]` — within [0..5] ✓
- `vsad[0]`, `vsad[1]`, `vsad[4]`, `vsad[5]` — within [0..5] ✓
- `nsse[0]`, `nsse[1]` — within [0..5] ✓
- `pix_abs[0][0..2]`, `pix_abs[1][0..2]` — within [0..1][0..3] ✓

The wrappers `nsse16_rvv_wrapper`/`nsse8_rvv_wrapper` (lines 62–78) check `if (c)` before dereferencing `c->c.avctx->nsse_weight`, guarding the null case. No external data flows into this file — it is purely CPU-feature detection and static function-pointer assignment. No allocations, no size arithmetic, no parsing of media container data.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

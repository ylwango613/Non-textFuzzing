**Key findings from full analysis:**

1. **`framectxid` → `prob_ctx[4]` index** (lines 47, 56): `framectxid` is set via `get_bits(&s->gb, 2)` (vp9.c:665) — a 2-bit field, strictly 0–3. Array has 4 elements. Safe.

2. **All loop-driven array accesses**: Every dimension matches the declared struct sizes in `VP9TileData.counts` and `ProbContext` — confirmed by comparing loop bounds (`i<4`, `j<2`, `k<2`, `l<6`, `m<6`; i<7; i<4/i<10; i<2; etc.) against the struct field declarations.

3. **`IntraPredMode` enum indices into count arrays**: DC_PRED=2, TM_VP8_PRED=9, VERT_PRED=0, HOR_PRED=1, DIAG_DOWN_RIGHT_PRED=4, VERT_RIGHT_PRED=5, HOR_DOWN_PRED=6, VERT_LEFT_PRED=7, HOR_UP_PRED=8 — all within the 10-element `y_mode[4][10]` / `uv_mode[10][10]` count arrays. `pp[]` write targets are 9-element `y_mode[4][9]` / `uv_mode[10][9]`, accessed pp[0]–pp[8]. Safe.

4. **`adapt_prob()`**: Writes only to the caller-supplied `uint8_t *p` pointer within a valid struct field. No dynamic allocation, no computed offsets.

5. **No `av_malloc`/`memcpy` with external sizes** anywhere in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

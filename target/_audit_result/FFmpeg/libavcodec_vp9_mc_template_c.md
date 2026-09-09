After thorough multi-pass analysis of `vp9_mc_template.c` and all related call chains in `vp9recon.c`, `vp9dsp.h`, and `vp9dec.h`, here is the complete audit summary:

**Checks performed:**
- `mc[5][N_FILTERS][2][2][2]` — first dimension max used = `bwl + ss_h = 3+1 = 4` (else branch), `4` hardcoded (if branch). Both ≤ 4, within bounds.
- `b->filter` (second dimension) — set only from `ff_vp9_filter_lut[0..2]` (values 0–2) or `s->s.h.filtermode` (0–3, never FILTER_SWITCHABLE=4 in this path). Within N_FILTERS=4 bounds.
- `b->mv[4][2]` — all accesses are `b->mv[0..3][0..1]`. Within bounds.
- `bwlog_tab[0][b->bs]` — `b->bs` is a validated enum 0–12; table has 13 entries.
- `ff_vp9_bwh_tab[ss_h][b->bs]` — `ss_h` is 0 or 1; table is `[2][N_BS_SIZES][2]`.
- `ROUNDED_DIV_MVx2/x4` on `int16_t` — promoted to `int` before addition; no overflow.
- `edge_emu_buffer[135*144*2]` — verified max writes (scaled: `134*288=38592 < 38880`; unscaled: `71*160=11360 < 38880`).
- `w2, h2, ref2, tref2` uninitialized-use risk — all uses are guarded by `if (b->comp)`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

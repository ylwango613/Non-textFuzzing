Based on my thorough analysis of all sections of `vp9dsp_12bpp.c` (which includes `vp9dsp_template.c` with `BIT_DEPTH=12` / `dctint=int64_t`), here is my conclusion:

**Batch 1 (lines 1–600)**: Intra prediction functions (`vert_*`, `hor_*`, `dc_*`, `tm_*`). All are guarded by `#if BIT_DEPTH != 12` (only `tm_*` and `dc_{128,127,129}_*` compile for 12bpp). These write into caller-allocated fixed-size destination blocks and read from fixed-size context-pixel arrays. No OOB possible.

**Batch 2 (lines 1155–1755)**: `itxfm_wrapper` macro instantiations for `idct4/8/16/32` and `iadst` with `dctcoef=int32_t`, `dctint=int64_t`. Stack arrays `tmp[sz*sz]` and `out[sz]` are exactly sized for the fixed `sz` (4/8/16/32) at compile time. All intermediate multiply-accumulate uses `int64_t`; no overflow possible.

**Batch 3 (lines 1780–1967)**: `loop_filter()` and its macro-expanded wrappers. Accesses `dst[strideb * ±8]` for `wd ≥ 16`, all relative to the caller's frame buffer pointer, which is bounds-checked upstream.

**Batch 4 (lines 2026–2113)**: `do_8tap_2d_c` uses `pixel tmp[64 * 71]`. Maximum `tmp_h = h + 7 = 71` for VP9's maximum block height 64. Exactly fits.

**Batch 5 (lines 2363–2409)**: `do_scaled_8tap_c` uses `pixel tmp[64 * 135]`. Maximum `tmp_h = (63 * dy + 15) >> 4 + 8`. With `dy ≤ 32` (derived from `mvstep = 16 * mvscale >> 14`, where `mvscale = (refw << 14)/w` and VP9 limits `refw ≤ 2w`): `tmp_h_max = (63*32+15)>>4 + 8 = 134 < 135`. The vertical-pass reads reach at most `tmp[8575]` vs. buffer bound `tmp[8639]`. Tight but correct.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

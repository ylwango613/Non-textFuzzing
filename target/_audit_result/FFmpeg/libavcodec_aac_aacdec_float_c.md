After reading all files included by `aacdec_float.c` — the DSP template, the processing template, the coupling and prediction headers, and tracing through the main `aacdec.c` decoder — I can now summarize the analysis findings.

Key areas checked:
- `saved` (1536 elems): max index in ELD mode = 3·n−1 = 1535 (n=512); fits exactly.
- `buf_mdct` (1024 elems): all MDCT variants write within bounds.
- `predictor_state` (672 elems): `swb_offset_1024_24[41] = 652 < 672`; fine.
- `ff_cbrt_tab` (8192 elems): escape code max `n = 8191`; fine.
- `ff_aac_pow2sf_tab` (428 elems, POW_SF2_ZERO=200): intensity/noise indices 100–355; fine.
- `band_type`/`sfo`/`sf` (128 elems each): max index `8×15−1 = 119`; fine.
- `coup->gain` [16][120]: max idx `8×15−1 = 119`; fine.
- TNS `order` validated ≤ `TNS_MAX_ORDER=20`; `lpc[20]` and `tmp[21]` fit.
- Pulse positions validated < `swb_offset[num_swb]` before any `coef_base[]` access.
- ELD window tables (`ff_aac_eld_window_512[1920]`, `ff_aac_eld_window_480[1800]`): max indices 1919 and 1799 respectively; exact fit.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

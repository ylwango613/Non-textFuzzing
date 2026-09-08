After reading the complete file (689 lines) and tracing all relevant data structures and array definitions, I've performed the following systematic checks:

**Group 1 (lines 41–111): dequant_scalefactors, apply_mid_side_stereo**
- `sfo[128]` / `sf[128]` / `band_type[128]` / `ms_mask[128]` — maximum index `(num_window_groups-1)*max_sfb + (max_sfb-1)` ≤ `8*15-1 = 119` for short windows (4-bit max_sfb), ≤ 62 for long windows. All within [0,127].
- `ff_aac_pow2sf_tab[428]` — sfo ranges [-100,155] (standard) or [-200,170] (USAC noise), giving tab indices [100,370], safely below 428.

**Group 2 (lines 120–219): apply_intensity_stereo, apply_tns**
- TNS order validated ≤ 20 = `TNS_MAX_ORDER`; `lpc[20]`, `tmp[21]` correctly sized.
- `coef[start]` and `coef[start ± i*inc]`: bounded by `w*128 + swb_offset[mmm] - 1` ≤ 1023 for all window types.

**Group 3 (lines 225–320): windowing_and_mdct_ltp, apply_ltp, update_ltp**
- `ltp->lag` decoded as 11-bit (0–2047); `ltp_state[3072]` access range [1,3071] — safe.
- `saved_ltp = coeffs[1024]`; all write paths cover exactly [0,1023].

**Group 4 (lines 325–602): imdct_and_windowing variants**
- `buf_mdct[1024]`: MDCT outputs (1024/960/768 samples) always fit.
- `saved[1536]`: ELD variant uses up to `3n-1` = 1535 (n=512) or 1439 (n=480).
- ELD `ff_aac_eld_window_512[1920]`/`ff_aac_eld_window_480[1800]`: max index accessed is `15n/4-1` = 1919/1799, exactly at boundary.
- `temp[128]`: vector_fmul_window writes at most 128 elements (2×64).

**Group 5 (lines 619–663): apply_prediction**
- `predictor_state[MAX_PREDICTORS=672]`: `swb_offset[ff_aac_pred_sfb_max[idx]]` gives at most 672 for all sampling rates — verified against tables.
- `reset_predictor_group`: `predictor_reset_group` validated [1,30]; step-30 loop stays within [0,671].

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

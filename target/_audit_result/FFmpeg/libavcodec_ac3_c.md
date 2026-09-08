**Full analysis summary:**

After reading all 294 lines of `ac3.c` in two passes, examining `ac3defs.h`, `ac3dec.h`, and tracing `start_freq`/`end_freq`/`sr_code`/`sr_shift` through `ac3dec.c` and `ac3_parser.c`:

1. **`ff_ac3_bin_to_band_tab[start]`** (line 187, 216): `start_freq` for regular channels = 0; for CPL_CH = `cpl_start_subband * 12 + 37` where `cpl_start_subband` ≤ 15 → max 217. All within the 253-element table.

2. **`ff_ac3_bin_to_band_tab[end-1]`** (line 217): `end_freq` max = `60*3+73 = 253` for regular channels, `18*12+37 = 253` for CPL_CH → `end-1 = 252`, valid index.

3. **`ac3_log_add_tab[adr]`** (line 195): `adr = FFMIN(…, 255)` ≤ 255 < 260; mathematically guaranteed ≥ 0 when `max = FFMAX(v, psd[bin])`.

4. **`excite[band]` / `band_psd[band]` / `mask[band]`**: all bounded to `band_end - 1` ≤ 49, within their 50-element arrays.

5. **`sr_code`**: parser rejects value 3 for AC-3; EAC-3 also stays ≤ 2 → `ac3_hearing_threshold_tab[…][sr_code]` second-dimension index [0..2] is always valid.

6. **DBA segment loop** (lines 279–291): checked `dba_nsegs > 8`, `band >= AC3_CRITICAL_BANDS`, `dba_lengths[seg] > AC3_CRITICAL_BANDS - band` — all bounds guarded correctly.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

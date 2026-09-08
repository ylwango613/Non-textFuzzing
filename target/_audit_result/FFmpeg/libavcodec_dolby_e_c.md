I've now completed a full multi-pass read of the entire file (all 1323 lines) plus `dolby_e_parse.c` and `dolby_e.h`. Here is a summary of what each analysis pass checked before the final verdict:

**Pass 1 (lines 1–600):** Static tables only — no code logic. Noted the array size constants: `MAX_EXPONENTS=304`, `MAX_MANTISSAS=1024`, `MAX_BIAS_EXP=50`.

**Pass 2 (lines 600–1000):** All decoding functions. Key checks:
- `unbias_exponents`: `bias_exp[MAX_BIAS_EXP=50]` filled up to `g->nb_exponent` and accessed up to `sum(nb_bias_exp[i])` = `g->nb_exponent`. Always equal. No OOB.
- `parse_channel` modification: `nb_exponent -= bw_code (0..7)`. Minimum original value is 38 (nb_bias_exp[1] min 23), so no uint8_t underflow.
- `parse_mantissas` `values[100]`: nb_mantissa_50[49]=100 is the global max; exactly sized.
- `mnt` pointer accumulation: all group mnt_ofs values, combined with their total nb_mantissa sums, exactly tile [0..1023] with no overflow.
- `parse_indices`: `start > g->nb_exponent` guard present before writing to `c->idx`.
- `c->exponents / c->bap / c->idx` [MAX_EXPONENTS=304]: max offset is exp_ofs=266, nb_exponent=38 → 266+37=303. Exactly fits.

**Pass 3 (lines 1000–1323):** Transform, gain, init, codec registration. Key checks:
- `imdct_calc` case 2: uses `imdct[0][idx]` (no `AV_TX_FULL_IMDCT`), so output is n/2 samples, not n samples → `buffer[1024..2047]` valid for idx=2.
- `transform`: all dst_ofs + win_len ≤ 1152 (result size); all src_ofs + win_len ≤ 2048 (buffer size); all win_ofs + win_len ≤ 3712 (window size).
- `apply_gain`: `begin_gain`/`end_gain` are 10-bit (0–1023), `gain_tab[1024]` valid for all.
- `filter_frame`: `reorder[ch]` arrays are sized for 4/6/8-channel configs and accessed only within bounds.
- `fast_gain_adj` pointer: max offset is 14 (nb_code=1) + max index 43 = 57 ≤ 61 (row size).

**Conclusion:** No memory safety vulnerabilities found. All external-input-derived values are properly bounded, all fixed-size buffers are exactly or safely sized, and no integer overflow/underflow paths lead to under-allocation or OOB access.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

After completing all four batches of the 1,824-line file plus tracing into every header, constant table, and called function, I have verified:

- `dexp[256]` in `decode_exponents`: max `ngrps*3 = 84*3 = 252 < 256` ✓  
- `dexps[]` destination write: bounded by `end_freq ≤ 253 < AC3_MAX_COEFS=256` ✓  
- `bnd_sz[22]` in `decode_band_structure`: max `n_subbands = 18 < 22` ✓  
- `output_buffer[EAC3_MAX_CHANNELS=16]` indexing: all paths produce indices 0..12 ✓  
- `ff_ac3_gain_levels[9]`: all accesses use 3-bit fields → indices 0..7 ✓  
- `outptr[AC3_MAX_CHANNELS=7]`: channel_map values max=5, ch-1 max=5 ✓  
- `cpl_band_sizes[AC3_MAX_CPL_BANDS=18]`, `spx_band_sizes[SPX_MAX_BANDS=17]`: `memcpy` sizes bounded ✓  
- `output[AC3_MAX_CHANNELS=7]` stack array: only accessed with `ch < out_channels ≤ 6` ✓  
- `scale_factors[25]` in float `dequantize_coeff`: `decode_exponents` validates `prevexp ≤ 24` before storing ✓  
- All integer arithmetic for `num_exp_groups`, channel counts, block counts uses values bounded by spec constants ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

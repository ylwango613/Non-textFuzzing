Having fully read the 448-line file and traced every key path through related headers (`aacdec.h`, `aactab.c`, `aacdec.c`, `aacdec_float_coupling.h`), I verified:

1. **`coup->gain[c][idx]`** (decode_cce): `num_gain ≤ 16` (c = 0..15 < dim-0 = 16); `num_window_groups * max_sfb ≤ 8×15 = 120`, body uses idx 0..119 < dim-1 = 120. Exactly at boundary but within bounds.
2. **memset size `(c − offsets[max_sfb])`**: `c = 1024/num_windows` (always 128 or 1024); swb_offset tables end at ≤ window size; expression always ≥ 0.
3. **`coef[]` writes**: stride is `g×128 + offsets[i]`, coeffs has 1024 elements; maximum address reached is coeffs+1023. In bounds.
4. **`ff_cbrt_tab[n]`**: `b ≤ 12`, `n ≤ 8191`; `LUT_SIZE = 8192`, valid indices 0–8191.
5. **`band_type[idx]`**: array has 128 elements; max idx = 119 < 128.
6. **`ics->num_windows`**: always set to 1 or 8 — no divide-by-zero in `1024/num_windows`.
7. **Pulse data**: `pos[i]` validated `< swb_offset[num_swb]` before use; `num_pulse ≤ 4`, `pos[4]` array large enough.
8. **do-while loop overruns**: all swb_offset tables use multiples-of-4 band sizes; `off_len` is always ≥ 4; no fractional iteration possible.

NO_VULN_FOUND

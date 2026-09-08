**Analysis summary** (618-line file, read in full):

**Key constants established:**
- `SUBFRAME_SIZE = 40`, `PITCH_DELAY_MAX = 143`, `PITCH_DELAY_MIN = 20`
- `RES_PREV_DATA_SIZE = 143 + 8 + 1 = 152`
- `ANALYZED_FRAC_DELAYS = 7`, `SHORT_INT_FILT_LEN = 2`, `LONG_INT_FILT_LEN = 8`

**Checked every potential concern:**

1. **`subframe_size` parameter** — passed as the compile-time constant `SUBFRAME_SIZE = 40` at the only call site (g729dec.c:705), never derived from untrusted bitstream. All stack buffers (`sig_scaled[192]`, `delayed_signal[7][41]`, `residual_filt_buf[51]`) are sized for exactly this value.

2. **`pitch_delay_int` lower-bound missing** — only an upper-bound clamp exists (g729dec.c:532–534). The minimum `pitch_delay_3x` from `ff_acelp_decode_8bit_to_1st_delay3` is 58 (with `ac_index = 0`), giving `pitch_delay_int = (58+1)/3 = 19`. The resulting `best_delay_int = 18`. Even at this minimum, the worst-case positive `sig_scaled` index is `152 - 18 + 1 + 40 + 7 = 182 < 192`. No OOB.

3. **`ff_acelp_interpolate` negative-side reads** — minimum index is `sig_scaled[152 - 144 + 0 - 8] = sig_scaled[0]`. Non-negative, within bounds.

4. **`ff_celp_lp_synthesis_filter` history access** — `lp_gn + 11` history reads go down to `lp_gn[1]` (zero from initial `memset`). `lp_gn[10]` is explicitly set to 4096 before the call. All within the 33-element `lp_gn` array.

5. **`pos_filter_data` writes** — `ctx->pos_filter_data[SUBFRAME_SIZE+10] = 50` elements. Writes go to indices 10–49, and `memcpy` at line 565 reads 40–49. All within bounds.

6. **`residual_filt_buf` long-filter write** — `long_term_filter` writes `subframe_size + 1 = 41` samples to `residual_filt_buf + 10`, reaching index 50. Buffer is 51 elements (0–50). Exactly fits.

7. **`corr_den[ANALYZED_FRAC_DELAYS][2]` and `delayed_signal[ANALYZED_FRAC_DELAYS][SUBFRAME_SIZE+1]`** — all loop indices bounded by `k < 7` and `i < 2`; `delayed_signal[k][40]` (the last access) is within the 41-element second dimension.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

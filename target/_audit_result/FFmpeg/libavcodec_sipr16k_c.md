After fully reading `sipr16k.c` and tracing every data path into related headers, codebook tables, and called functions, I performed the following specific checks:

**1. `dequant()` codebook array access (lines 53–61)**
`idx[]` = `params->vq_indexes[]` from `get_bits(pgb, bits[i])` with `{7,8,7,7,7}` bits.
- `cbs[0..3]` (size 128×3=384 floats): max offset = 3×127=381 → reads offsets 381–383 ✓
- `cbs[1]` (256×3=768 floats): max offset = 3×255=765 → reads offsets 765–767 ✓
- `cbs[4]` (128×4=512 floats): max offset = 4×127=508 → reads offsets 508–511 ✓

**2. Gain codebook accesses (lines 220, 241)**
- `gain_pitch_cb_16k[params->gp_index[i]]`: 4-bit index 0–15, array has 16 elements ✓
- `gain_cb_16k[params->gc_index[i]]`: 5-bit index 0–31, array has 32 elements ✓

**3. `qu[ma_pred]` in `lsf_decode_fp_16k` (line 72)**
`ma_pred_switch` is 1 bit → 0 or 1. `qu` has 2 elements ✓

**4. `ff_acelp_interpolatef` / `sinc_win` (line 228)**
`sinc_win` is declared `[40]` with 30 explicit values (rest zero-initialized). Inner loop max filter index = 30 ≤ 39 ✓

**5. `excitation` buffer backward/forward access**
Buffer: `ctx->excitation[L_INTERPOL + PITCH_MAX + 2×L_SUBFR_16k] = [452]`. With `excitation = ctx->excitation + 292`, max `pitch_delay_int ≈ 282`, backward access lands at `ctx->excitation[81]` at minimum ✓

**6. `ff_decode_10_pulses_35bits` → `ff_set_fixed_vector`**
`gray_decode[fixed_index & 0xF]` index is 0–15, table has 16 elements. Result capped to 75+4=79 < `L_SUBFR_16k=80` ✓

**7. `ff_pow_0_5`, `filt_buf`, `iir_mem`**
All 16-element loops access 17-element arrays ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

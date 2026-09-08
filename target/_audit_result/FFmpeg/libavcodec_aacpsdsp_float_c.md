After thoroughly reviewing `aacpsdsp_float.c` and its template (`aacpsdsp_template.c`), plus tracing all call chains through `aacps.c` and `aacps_common.c`, I can confirm:

1. **All `len` / `n` parameters are hardcoded constants** — `nL - n0 = 32`, `numQMFSlots = 32` (macro), `const int len = 32` in `ff_ps_apply`. None derive from untrusted input.
2. **`ap_delay` bounds are correct by design** — the write `ap_delay[m][n+5]` with n ∈ [0,31] gives max index 36; the array has 37 elements (`PS_QMF_TIME_SLOTS + PS_MAX_AP_DELAY = 37`).
3. **`border_position` values are bounded** — read via `get_bits(gb, 5)` (0–31), forced monotone, and capped at `numQMFSlots - 1 = 31`. The `stereo_interpolate` `len = stop - start` stays within the 32-element arrays.
4. **No dynamic allocation in these functions** — all buffers are fixed-size stack or struct arrays; no `av_malloc`/`memcpy` driven by file-provided sizes exists here.
5. **Stride access pattern in `ps_hybrid_analysis_c`** — stride=32 intentionally indexes across rows of the 2D output array; the accessed `out[j][i]` stays within `[91][32][2]` bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

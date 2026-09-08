After completing the full analysis:

**File scope:** `aacpsdsp_template.c` is a DSP kernel template containing 8 pure math functions initialized as function pointers in `PSDSPContext`. All arrays operated on are statically allocated in `PSContext` with fixed compile-time dimensions.

**Key findings after tracing all calling chains:**

1. `ps_decorrelate_c` — The most suspicious function. Writes `ap_delay[m][n+5]` and reads `ap_delay[m][n+2-m]`. Second dimension is `PS_QMF_TIME_SLOTS + PS_MAX_AP_DELAY = 32+5 = 37` (valid 0..36). Called with `len = nL - n0 = 32 - 0 = 32` (hardcoded in `decorrelation()` at `aacps.c:414`). Max write index: `31+5 = 36` — exactly at boundary. Max read index: `31+2-0 = 33` — within bounds. No overflow.

2. `ps_hybrid_analysis_ileave_c` / `ps_hybrid_synthesis_deint_c` — Both called with fixed `len=32` from `ff_ps_apply` (line 723: `const int len = 32`). All array accesses within statically-bounded `Lbuf[91][32][2]` / `Rbuf[91][32][2]`.

3. `ps_hybrid_analysis_c` — Accesses `in[12-j]` for j=0..5 (max index 12) and `in[6]`. Caller advances `in` by 1 per iteration over `len=32` steps from `in[0]` of `in_buf[5][44][2]`. Max access: `in[31+12] = in[43]` — exactly at boundary of 44-element array.

4. All other functions (`ps_add_squares_c`, `ps_mul_pair_single_c`, `ps_stereo_interpolate_c`, `ps_stereo_interpolate_ipdopd_c`) — iterate `n < len` with `len=32` on arrays sized exactly 32.

No externally controlled value flows into any loop bound, allocation size, or array index. All DSP parameters are compile-time constants.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

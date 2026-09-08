After thoroughly reading the entire `dcadsp.c` (494 lines, all batches), tracing every function's call sites in `dca_core.c`, `dca_lbr.c`, and `dca_xll.c`, and checking all critical constraints:

**Batch 1 analysis (lines 1–300):** `decode_hf_c` — `vq_index[i]` is bounded to `[0, 1023]` by `get_bits(&s->gb, 10)` (10-bit read), matching `hf_vq[1024][32]`; `scale_factors[i][0]` with `i < nsubbands[ch]` is bounded since `nsubbands` is validated ≤ `DCA_SUBBANDS=32` at parse time. `lfe_fir_fixed_c`'s `lfe_samples[-k]` is safe because callers pass `s->lfe_samples + DCA_LFE_HISTORY` (=8) and `k ≤ 7`. All other DSP primitives loop over fixed-size inner products with no external-input indices.

**Batch 2 analysis (lines 300–494):** `lbr_bank_c` writes `output[i][0..3]` for `i < len` (where `output` is `float[32][4]`). Apparent OOB if `len > 32`. However, `len = nsubbands = 8 << limited_range`; all valid LBR sample rates are gated at `> 48000 Hz → AVERROR_PATCHWELCOME`, so `freq_range ≤ 2` and `limited_range ≤ 2`, giving `nsubbands ≤ 32`. The aliasing loop `i < len - 1` starting at 12 accesses `output[len-1]` at most, within bounds. `assemble_freq_bands_c`'s `src0` underrun is intentional: the caller copies decimator history at `band0 - DCA_XLL_DECI_HISTORY_MAX` before the call. `lfe_iir_c` iterates exactly 64 × `factor` output samples; output buffers are sized accordingly.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

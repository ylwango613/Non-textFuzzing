After extensive multi-pass analysis of the entire `silk.c` file (902 lines) plus all relevant tables, headers, and calling code in `dec.c`, I traced every array access, computed bounds for every CDF-decoded symbol used as an index, verified all stack buffer sizes against maximum shellblocks/subframes/order combinations, and checked all negative-index accesses in the LTP re-whitening and synthesis loops.

Key findings from each analysis group:

**Group 1 (lines 1–311):** `silk_stabilize_lsf`, `silk_is_lpc_stable`, `silk_lsp2poly`, `silk_lsf2lpc` — all array accesses (`p[9]`, `q[9]`, `lpc32[16]`, `lsp[16]`) sized correctly. `ff_silk_cosine[index+1]` max index = 128, table has 129 entries (0..128). Negative `nlsf` values after stabilizer push-backward are impossible because push-forward establishes a lower bound that satisfies all constraints.

**Group 2 (lines 312–500):** `silk_decode_lpc`, `silk_decode_excitation` — `lsf_i1` range 0..31, all codebook/weight tables have first dimension 32. `shellblocks` max = 20, `pulsecount[20]`/`lsbcount[20]` sized correctly. Max `shellblocks*16 = 320` writes to `excitationf`, which has 322 slots (`residual[612]` starting at `SILK_MAX_LAG=290`).

**Group 3 (lines 509–736):** `silk_decode_frame` — re-whitening negative-index accesses `dst[-290]` to `dst[-306]` resolve to `frame->output[16..32]` (well within the 644-float array). LTP synthesis `resptr[-290]` = `residual[0]` (min), in bounds. `sf[i].pitchlag` is clipped to `[min_lag, max_lag]` before use. `frame->output` and `lpc_history` (644 floats each) exactly accommodate max WB 4-subframe writes ending at index 641.

**Group 4 (lines 786–864):** `ff_silk_decode_superframe` — `active[2][6]` and `redundancy[2]` sized correctly for max `coded_channels=2` and `nb_frames=3`. LTP filter table indices (0..7, 0..15, 0..31) match table dimensions `[8][5]`, `[16][5]`, `[32][5]`. Stereo weight index `wi[i]` max = 14, `ff_silk_stereo_weights[15]` is valid (16-entry array). Caller's `silk_buf[2][960]` accommodates max `3 * 320 = 960` returned samples.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

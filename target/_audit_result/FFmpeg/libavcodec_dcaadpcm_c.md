After thorough analysis of `dcaadpcm.c` and its full call chain:

**Group 1 — Core logic (lines 1–103):** `calc_corr`, `apply_filter`, `find_best_filter`: fixed-size stack arrays (`corr[15]`) filled by a loop producing exactly 15 iterations (triangular sum 5+4+3+2+1). No overflow.

**Group 2 — Subband analysis (lines 126–163):** `ff_dcaadpcm_subband_analysis` uses `input_buffer[20]` and loops `len + DCA_ADPCM_COEFFS` iterations. `len = SUBBAND_SAMPLES = 1×2×8 = 16`; buffer is exactly 20. Tight fit, but the caller (encoder only, `dcaenc.c:661`) always passes the compile-time constant `SUBBAND_SAMPLES = 16`. Not externally reachable with attacker-controlled `len`.

**Group 3 — ADPCM reconstruction (lines 184–211):** `ff_dcaadpcm_do_real` uses `work_bufer[20]`. Loop writes `work_bufer[4..19]` when `len = 16`. Final `memcpy` reads `work_bufer[16..19]`. Exactly within bounds.

**Group 4 — Decoder path (dca_core.c:619):** The only external-input path: `pred_id = vq_index[i]` from `get_bits(&s->gb, 12)` → value range 0..4095. Table `ff_dca_adpcm_vb[DCA_ADPCM_VQCODEBOOK_SZ]` has exactly 4096 entries. All valid bit patterns are valid indices — no OOB.

**Group 5 — Init/precalc (lines 165–232):** `precalc` fills exactly 10 entries per `premultiplied_coeffs[10]` (loop count = 4+3+2+1 = 10). Allocation in `ff_dcaadpcm_init` is straightforward with no integer overflow risk.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

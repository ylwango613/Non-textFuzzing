The file `vp56data.c` is 255 lines of exclusively static constant data tables — no functions, no memory allocations, no pointer arithmetic, and no external input processing. I've verified:

- All array sizes match their `extern` declarations in `vp56data.h`.
- All callers use validated indices:
  - `ff_vp56_b2p[b+ab]`: max index 9, array has 10 elements — safe.
  - `ff_vp56_b6to4[b]`: loop `b < 6`, array has 6 elements — safe.
  - `ff_vp56_ac/dc_dequant[quantizer]` / `ff_vp56_filter_threshold[quantizer]`: quantizer masked to 6 bits (0–63), arrays have 64 elements — safe.
  - `ff_vp56_reference_frame[mb_type]`: `VP56mb` enum is 0–9, array has 10 elements — safe.
  - `ff_vp56_pre_def_mb_type_stats[idx]`: `idx = vp56_rac_gets(c, 4)` → 0–15, array has 16 elements — safe.
  - `ff_vp56_candidate_predictor_pos[pos]`: loop `pos < 12`, array has 12 elements — safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

After thorough analysis of `aptxenc.c`, `aptx.h`, and `aptx.c`, including:

- The `output_size` integer arithmetic (bounded by enforced `frame_size=1024`, max `6*1024/4=1536`)
- `aptx_bin_search` index bounds (all table sizes are power-of-2+1: 3,5,9,17,33,65,257 — max idx is always `table_size-2`, so `intervals[idx+1]` is always in-bounds)
- `aptx_reconstructed_differences_update` / `aptx_prediction_filtering` indexing into the 48-element `reconstructed_differences` buffer with orders up to 24
- `d_weight[24]` accesses for all `prediction_order` values (6, 12, 24)
- Frame data access pattern at line 238 (max byte index `4*(nb_samples-1)+3`, within allocated buffer)
- No heap allocations in the encode hot path — all state lives in the fixed `AptXContext`

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

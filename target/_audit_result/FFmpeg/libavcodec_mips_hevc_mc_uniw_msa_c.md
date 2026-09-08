I've now read through the entire 6349-line file in systematic batches, examining every function group:

**Group 1 (lines 1-640):** Copy functions (4w through 64w) — loop counts driven by `height` or `height>>n` correctly.

**Group 2 (lines 643-1428):** 8-tap horizontal filter (4w through 64w) — 24w and 48w use hardcoded `loop_cnt=16` (32 rows) and `loop_cnt=64` (64 rows), ignoring `height`. Investigated whether these cause OOB: in HEVC, 24-wide blocks only arise from AMP of 32×32 CU (always height=32) and 48-wide from AMP of 64×64 CU (always height=64). These hardcodings match the only valid heights.

**Group 3 (lines 1430-2010):** 8-tap vertical filter — same pattern; 24w passes hardcoded `32`, 48w passes hardcoded `64` to sub-functions; valid in HEVC spec context.

**Group 4 (lines 2011-2590):** 8-tap HV filter — 12w hardcodes 16 rows; valid (12-wide always height=16 in HEVC AMP of 16×16 CU).

**Group 5 (lines 2591-3506):** 4-tap horizontal filter — 12w uses `height>>2` correctly; 8w dispatches by height; 24w hardcodes 32 rows matching spec.

**Group 6 (lines 3507-4400):** 4-tap horizontal/vertical 24w — hardcoded 32 matches spec. 4-tap vertical 12w hardcoded 16 rows matches spec.

**Group 7 (lines 4400-5950):** 4-tap vertical functions — hardcoded loop counts match expected HEVC block heights for each width. 24w=32, 12w=16.

**Group 8 (lines 5950-6349):** 4-tap HV functions — 12w hardcodes 16 rows total matching spec; dispatch wrappers otherwise correct.

**Cross-cutting analysis:**
- No heap allocations in this file — no malloc/realloc to missize.
- `src -= 3` / `src -= (3 * src_stride)` sub-filter-tap accesses are within FFmpeg's standard frame padding.
- SIMD mask array `ff_hevc_mask_arr[32]` accesses via pointer arithmetic stay within bounds.
- No integer overflow paths: all arithmetic is on bounded pixel values within SIMD registers.
- All hardcoded row counts match the only valid heights mandated by the HEVC specification for those block widths; the HEVC decoder validates block geometry before dispatching to these functions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

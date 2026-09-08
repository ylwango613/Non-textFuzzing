I have now read the complete file (2300+ lines) in four batches and traced all related headers, filter tables, and the calling context in `vp8.c`. Let me summarize my findings:

**Batch 1 (lines 1–600):** All filter table accesses use `subpel_filters_msa[mx - 1]` / `[my - 1]`. The table has 7 entries (indices 0–6). In `vp8.c`, `mx = (mv->x * 2) & 7` and `my = (mv->y * 2) & 7` are masked to [0, 7], and filter functions are only dispatched via `mc_func[my_idx][mx_idx]` where `mx_idx = subpel_idx[0][mx]` — a non-zero index (selecting a filter function) only occurs when `mx ≥ 1`, making the access `subpel_filters_msa[mx - 1]` always in-range [0–6]. Same analysis applies to `bilinear_filters_msa`.

**Batch 2 (lines 600–1200):** Loop patterns `for (loop_cnt = (height >> 2); loop_cnt--;)` use `uint32_t` counters. With post-decrement, when `loop_cnt = 0`, the loop body is never entered. VP8 block heights are always 4, 8, or 16 — so `height >> 2 ≥ 1` always.

**Batch 3 (lines 1200–1800):** Bilinear filter functions follow identical safe index patterns. No unchecked allocation or `memcpy` with external size.

**Batch 4 (lines 1800–2300):** `common_vt_2t_8x8mult_msa` uses `height >> 3` iterations; called only with height ≥ 8 from `vp8.c`. All SIMD loads reading 16-byte vectors on 4-wide blocks are safe because FFmpeg frames include `AV_INPUT_BUFFER_PADDING_SIZE` bytes and edge emulation fills the buffer with correct guard rows/columns before these functions are called.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

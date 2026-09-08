Analysis complete. Here is my summary of what was examined across all 946 lines:

**Batch 1 (0-600):** Examined `put_pcm`, `add_residual`, `dequant`, `transform_rdpcm`, the IDCT macro family, and all QPEL bi-pred interpolation functions including `put_hevc_qpel_bi_hv`.

- `put_pcm`: `pcm_bit_depth` is read from SPS as 4-bit field +1 (1..16), and ps.c line 1499-1503 returns `AVERROR_INVALIDDATA` if it exceeds `sps->bit_depth`. So `BIT_DEPTH - pcm_bit_depth >= 0` at call time. No negative shift.
- `dequant`: `shift = 15 - BIT_DEPTH - log2_size`. BIT_DEPTH is 8/9/10/12 (compile-time constants from dsp.c lines 112-126). SPS ps.c line 1704 clamps `log2_max_trafo_size` to `FFMIN(log2_ctb_size, 5)` and returns error otherwise. So log2_size ∈ [2,5], giving shift ∈ [2,5] for 8-bit, always safe in the `BIT_DEPTH<=9` always-true branch.
- `transform_rdpcm`: same log2_size bound applies; size = 1<<5 = 32 max.
- `tmp_array` in `put_hevc_qpel_bi_hv` (line 497): `(MAX_PB_SIZE + QPEL_EXTRA) * MAX_PB_SIZE = (64+7)*64 = 4544` elements. Maximum writes: `(height+7)*64`. Since `height <= MAX_PB_SIZE = 64` (HEVC CTB max), writes = exactly 4544. Tight but correct.

**Batch 2 (600-946):** Examined EPEL bi-pred functions, deblocking filter.

- `tmp_array` in `put_hevc_epel_bi_hv` (line 693): `(MAX_PB_SIZE + EPEL_EXTRA) * MAX_PB_SIZE = 67*64 = 4288` elements. Maximum writes: `(height+3)*64 = 67*64 = 4288`. Correct.
- Filter index accesses: `ff_hevc_qpel_filters[mx]` uses `mx = mv->x & 3` (0..3), array is [4][16] — in bounds. `ff_hevc_epel_filters[mx]` uses `av_zero_extend(mv->x, 2+hshift)` (0..7), array is [8][4] — in bounds.
- Deblocking functions: all operate on caller-bounded buffers, no OOB path.

**SPS validation summary:** All critical parameters that feed dsp_template.c functions are validated upstream — log2_trafo_size bounded [2,5], pcm_bit_depth ≤ bit_depth, block dimensions ≤ 64.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

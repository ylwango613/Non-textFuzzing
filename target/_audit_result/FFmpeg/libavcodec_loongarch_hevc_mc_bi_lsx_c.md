I've completed a thorough multi-pass analysis of the entire 2184-line file. Let me summarize findings from each section:

**Batch 1 (lines 1–600):** `hevc_bi_copy_*w_lsx` functions — all use `_src1 = src1_ptr + 8` auxiliary pointers that are advanced consistently with `src1_ptr` in both main loops and tail loops. No stride arithmetic overflow is possible because `src2_stride = MAX_PB_SIZE = 128`, giving `src2_stride_2x = 512`, well within `int32_t` range.

**Batch 2 (lines 600–1200):** `hevc_hz_8t_*` and `hevc_vt_8t_*` functions — the dual-pointer `(_src1, src1_ptr)` pattern for wide cases (16w+) is consistent. The byte-offset semantics of `__lsx_vldx` vs. element-count semantics of `+=` are consistently paired throughout.

**Batch 3 (lines 1200–1800):** `hevc_hz_4t_24w_lsx`, `hevc_vt_4t_*w_lsx`, and `hevc_hv_4t_8x2_lsx` — the `src1_ptr_tmp = src1_ptr + 16` auxiliary pointer in `hz_4t_24w` advances correctly by 4 rows per main-loop iteration, matching `src1_ptr`'s 4 individual advances. No desync possible.

**Batch 4 (lines 1800–2184):** `hevc_hv_4t_8*` and the macro dispatch wrappers — `BI_MC_COPY` passes `MAX_PB_SIZE` as `src2_stride`, keeping all strides bounded. `hevc_hv_4t_8multx4_lsx`'s `src0_ptr += (8 - src_stride_4x)` column-advance correctly compensates for the in-body `+= src_stride_4x` to move to the next 8-pixel column.

**Key negative findings:**
- No `av_malloc` / memory allocation in this file; it is a pure computation kernel
- All pointer pre-adjustments (e.g., `src0_ptr -= 3` for 8-tap H, `src0_ptr -= src_stride_3x` for 8-tap V) match the filter tap count exactly
- Height residuals (`res = (height & 7) >> 1` etc.) only produce values that are valid HEVC partition sub-multiples; odd heights don't occur for these widths in conforming HEVC bitstreams
- All SIMD store widths exactly match the function's declared output width (e.g., `hevc_bi_copy_6w_lsx` uses `vstelm_w + vstelm_h` for 4+2 = 6 bytes)
- No stack buffers; all local state is in SSE/LSX registers or stack `__m128i` values

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

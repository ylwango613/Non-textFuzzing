I have now completed a thorough analysis of `vp9dsp.c` and all related implementation files. Here is my conclusion:

**Analysis Summary:**

1. **`vp9dsp.c` (112 lines):** Contains only a compile-time constant filter table (`ff_vp9_subpel_filters[3][16][8]`) and the `ff_vp9dsp_init()` dispatch function. No memory allocations or dynamic data operations — no memory-safety issues possible here.

2. **`vp9dsp_template.c` (the actual implementation):** Thoroughly examined all DSP operations:
   - **Intra-prediction functions:** All use fixed-size stack arrays matched to their transform sizes; accesses are within bounds.
   - **IDCT/IADST transform functions:** Stack buffers `tmp[sz*sz]` and `out[sz]` correctly sized. The `dctcoef` cast from `int16_t*` is safe because the block buffer is allocated with `bytesperpixel * sizeof(int16_t)` bytes per coefficient to accommodate `int32_t` for 10/12-bit depth.
   - **Loop filter:** All accesses at fixed offsets; no allocation.
   - **Non-scaled MC (`do_8tap_2d_c`, `do_bilin_2d_c`):** Stack buffers `tmp[64*71]` and `tmp[64*65]` are correctly sized for max block height (64) plus filter taps.
   - **Scaled MC (`do_scaled_8tap_c`, `do_scaled_bilin_c`):** Carefully verified. `tmp[64*135]` and `tmp[64*129]` are correctly sized: VP9 limits reference frame scaling to 2:1 (enforced at `vp9.c:867` with `if (w * 2 < refw)`), giving `mvstep` max = 32. With max `h=64`, `dy=32`, `my=15`: `tmp_h = 134 ≤ 135`. The buffer is tight but correct.
   - **Filter index lookups:** `imx` and `my` are always masked to 0–15 before indexing `filters[16]`. ✓

No externally-triggerable memory-safety vulnerabilities found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

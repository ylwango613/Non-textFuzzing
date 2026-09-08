Having read the entire file (3142 lines) in five batches and traced all memory access patterns:

**Batch 1 (1–600):** Macro definitions and initial `ff_loop_filter_v_*` functions. All accesses use `dst ± stride*N` (negative/positive offsets). Strides come from the VP9 decoder context, not directly from the bitstream content. Stack-allocated SIMD vectors only.

**Batch 2 (600–1200):** `vp9_hz_lpf_t4_and_t8_16w` writes to `filter48` at offsets 0, 16, 32, 48, 64, 80, 96 (7 × 16 = 112 bytes). `ff_loop_filter_v_16_16_lsx` allocates `filter48[16*8]` = 128 bytes → 112 < 128, no overflow. `vp9_hz_lpf_t16_16w` reads from `filter48[96]` and frame buffer rows ±8 strides; all within caller-allocated bounds.

**Batch 3 (1200–1800):** Remaining `ff_loop_filter_v_*` and `ff_loop_filter_h_*` variants. All load/store fixed 16-byte SIMD vectors at stride-separated offsets in the VP9 frame buffer. No dynamic-size allocations.

**Batch 4 (1800–2400):** `vp9_transpose_16x8_to_8x16` writes 16 × 16 = 256 bytes to `transposed_input`. `ff_loop_filter_h_16_8_lsx` allocates `transposed_input[16*24]` = 384 bytes; `filter48 = &transposed_input[256]`, last write ends at offset 368 < 384. LSX_LD_8/LSX_ST_8 macros self-increment the pointer, and the extra `+= stride4` after the first macro call correctly advances to row 8 (not a double-increment bug).

**Batch 5 (2400–3142):** `vp9_vt_lpf_t16_8w` and `vp9_vt_lpf_t16_16w` both set `dst_tmp = dst - 128 = transposed_input + 0` and read/write within the 384-byte buffer. The `dst -= 7*16` adjustment yields 14 sequential writes ending at offset 224+15=239 < 384. `ff_loop_filter_h_16_16_lsx` follows the identical buffer pattern.

**Key observations:**
- All stack buffers (`filter48[128]`, `transposed_input[384]`) are correctly sized for their usage.
- No heap allocations in this file whatsoever.
- No data-dependent index arithmetic (accesses are to fixed SIMD-width offsets).
- Parameters `b_limit_ptr`, `limit_ptr`, `thresh_ptr` are scalar values truncated to 8-bit by `__lsx_vreplgr2vr_b`; VP9 bitstream bounds (0–127) prevent any issue.
- `ptrdiff_t stride` truncated to `int32_t` in `vp9_transpose_16x16` is bounded by VP9 max frame width (16384).
- `VP9_FLAT4` macro references free variable `mask` from enclosing scope — bad practice but all call sites define it.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

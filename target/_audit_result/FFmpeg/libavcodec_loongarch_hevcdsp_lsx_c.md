After reading all 3250 lines of `hevcdsp_lsx.c` in five batches and cross-checking the header and key constants, I have completed a thorough analysis.

**Summary of analysis:**

The file contains LoongArch LSX SIMD motion-compensation kernels for HEVC (copy, 8-tap horizontal/vertical/bilinear filter, 4-tap variants). Key patterns examined:

1. **Stride integer overflow** — All stride multiplications (`src_stride << 1/2/3`) are with `int32_t`. For realistic HEVC frame widths (≤ 8192), `4 × stride ≤ 32768`, well within `int32_t`. No overflow.

2. **OOB src reads for filter lookahead** — Functions pre-adjust `src -= 3` (horizontal 8-tap) or `src -= src_stride_3x` (vertical 8-tap) before SIMD vector loads that span beyond the nominal block edge. This is architecturally required for convolution filters and is protected by the mandatory `AV_INPUT_BUFFER_PADDING_SIZE` padding allocated by the frame allocator. Not a bug.

3. **SIMD 16-byte load beyond block width** — In `hevc_copy_4w_lsx` and `hevc_hz_8t_4w_lsx`, a 16-byte `__lsx_vld` is used for a 4-byte-wide block. The extra 12 bytes read are within the allocated frame padding. Not exploitable.

4. **`hevc_copy_16w_lsx` residual block writes 4 rows when `res != 0`** — The `if (res)` tail always writes rows 0–3 regardless of `res`. For 16-wide blocks HEVC permits only heights that are multiples of 4, so `res` ∈ {0, 4} in practice. A height of 1, 2, 3, 5, 6, 7 would be a spec violation caught earlier in the decoder.

5. **`ff_hevc_mask_arr` access** — The constant array is exactly 32 bytes; all loads are at offsets 0 and 16 for 16-byte reads. No OOB.

6. **No malloc/realloc/memcpy of untrusted sizes** — The entire file is pure compute logic with no memory allocation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

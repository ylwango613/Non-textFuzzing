No `av_malloc`/`memcpy`/`memset` calls anywhere in the file. All memory operations are fixed-size SIMD intrinsics on pre-allocated frame buffers.

**Analysis summary across all 783 lines:**

- No dynamic heap allocation in this file — zero `av_malloc`/`av_realloc`/`memcpy` calls.
- All functions (`ff_h264_h_lpf_luma_8_lasx`, `ff_h264_v_lpf_luma_8_lasx`, `ff_h264_h_lpf_luma_intra_8_lasx`, `ff_h264_v_lpf_luma_intra_8_lasx`, `ff_h264_add_pixels4_8_lasx`, `ff_h264_add_pixels8_8_lasx`) are SIMD-optimized in-place frame buffer operations.
- All SIMD loads/stores use fixed 256-bit (32-byte) register widths on caller-provided frame pixel buffers.
- `img_width` (ptrdiff_t) is truncated to `int` at lines 70-73, 247-248, 409-411, but H.264 codec validates frame dimensions (max width 65535 px) well below INT_MAX/8, making practical overflow unreachable.
- Parameters `alpha`, `beta`, `tc` are bounded by H.264 spec and clamped upstream in `h264_slice.c` before reaching these functions.
- Duplicate SIMD op at line 761 is a redundant instruction (performance/logic bug) with no memory safety consequence.
- All `__lasx_xvstelm_d`/`__lasx_xvstelm_w` element indices are within the valid 0-3 (doubleword) or 0-7 (word) range for 256-bit LASX registers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

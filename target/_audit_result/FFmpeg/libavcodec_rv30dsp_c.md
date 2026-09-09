After a thorough analysis of `rv30dsp.c` (319 lines), including:

- Full read of the file across all its macro-generated DSP functions
- Examination of `rv34dsp.h` to check `RV34DSPContext` array bounds (`put_pixels_tab[2][16]`, `avg_pixels_tab[2][16]`)
- Tracing the calling code in `rv34.c::rv34_mc()` to verify:
  - `dxy = ly*4 + lx` where lx,ly ∈ {0,1,2} for thirdpel (RV30), giving dxy ∈ {0,1,2,4,5,6,8,9,10} — all within the 16-element array and matching exactly the indices initialized in `ff_rv30dsp_init`
  - `motion_val` is `int16_t` and the expression `(motion_val[0] + (3 << 24)) % 3` always yields a safe, positive modulo
  - The edge emulation buffer in `rv34_mc` is sized `(width<<3)+6` × `(height<<3)+6` and the srcY offset `+2+2*linesize` provides the required 1-2 row/column padding for all lowpass functions
- Verification that the `op_put`/`op_avg` macros use `cm[b]` (`ff_crop_tab + MAX_NEG_CROP`) which safely clamps any integer value to [0,255]

Key findings per function group:
- **h_lowpass**: accesses src[-1..9] per row — standard padding, covered by edge emulation ✓
- **v_lowpass**: accesses src[-srcStride..9*srcStride] per column — 1 row above, 2 rows below block, within 14-tall buffer ✓
- **hv/hhv/hvv_lowpass**: accesses src[-srcStride-1..2*srcStride+9] — covered by edge emulation ✓
- **hhvv_lowpass**: accesses only src[0..2*srcStride+9] (no negative offsets) ✓
- **ff_rv30dsp_init**: assigns to fixed indices [0,1,2,4,5,6,8,9,10] — all within bounds of the 16-element array ✓

The file contains no dynamic memory allocation, no user-controlled buffer sizes, no integer arithmetic used to derive allocation sizes, and no unchecked external data driving any memory operations. All source access patterns are fixed relative to properly emulated frame edge buffers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

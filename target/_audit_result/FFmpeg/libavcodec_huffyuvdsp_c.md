After thorough analysis of `huffyuvdsp.c` (98 lines) and its complete call chain in `huffyuvdec.c`:

- **`add_int16_c`**: The `*(long*)(src+i)` aliasing trick is intentional (FFmpeg builds with `-fno-strict-aliasing`). Loop bounds are safe: the first loop stops at `w - sizeof(long)/2` elements, the tail loop covers the remainder. No OOB possible.

- **`add_hfyu_median_pred_int16_c`**: Straightforward bounded loop `for(i=0; i<w; i++)` accessing `src[i]`, `diff[i]`, `dst[i]`. No issues.

- **`add_hfyu_left_pred_bgr32_c`**: `i` is `int`, `w` is `intptr_t`. The `4 * i` expression could theoretically overflow for huge `i`, but `w` always comes from `avctx->width` (an `int`) at call sites (lines 1199, 1205 of `huffyuvdec.c`). The `s->temp[0]` buffer is allocated as `4 * avctx->width + 16` bytes (line 609), exactly matching the access pattern. No exploitable OOB.

All three functions are pure DSP computation helpers that trust callers to pass valid, pre-validated frame dimensions. No memory allocation, no external input parsing, and no independently triggerable memory safety defect exists within this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

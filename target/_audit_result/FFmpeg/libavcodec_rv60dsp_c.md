Based on my thorough analysis of `rv60dsp.c` and its full calling context in `rv60dec.c`, let me confirm the key safety properties:

**rv60dsp.c (165 lines)**: Three IDCT functions — `ff_rv60_idct4x4_add`, `ff_rv60_idct8x8_add`, `ff_rv60_idct16x16_add`. Each uses correctly-sized stack buffers (`int tmp[16]`, `int tmp[64]`, `int16_t tmp[256]`) and the block-read indices stay within bounds for their expected 4×4/8×8/16×16 input sizes. Intermediate `int` arithmetic cannot overflow (max ~12.5M vs INT_MAX ~2.1B). The `av_clip_intp2(x, 15)` intermediate clip keeps values within `int16_t` range for the 16×16 case.

**Coefficient buffers in rv60dec.c**: `y_coeffs[256]`, `u_coeffs[64]`, `v_coeffs[64]` are correctly sized for their respective IDCT calls. All decode functions (`decode_cu_4x4in16x16`, `decode_cu_8x8`, `decode_cu_16x16`) write within these bounds.

**pred_angle overflow check**: The `filtered1[96]` stack buffer could theoretically overflow (`filter_bilin32(filtered1+64, ..., add_size)` with large `add_size`), but the critical size-64 CU case is gated at decode time: 64×64 intra CUs can only have `cu.imode[0] ∈ {INTRAMODE_PLANE64, INTRAMODE_DC64}`, which maps to `imode ∈ {0, 1}` → only `pred_plane`/`pred_dc` branches are executed, never touching `filtered1`. For size=32 (the largest CU with arbitrary imode), the maximum `add_size` is 32 (imode=34), filling `filtered1[64..95]` — exactly at the boundary, not past it.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

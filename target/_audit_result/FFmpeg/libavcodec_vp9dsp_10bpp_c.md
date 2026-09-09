I've now thoroughly read and analyzed the complete `vp9dsp_template.c` (which is what `vp9dsp_10bpp.c` compiles, with `BIT_DEPTH=10` and `dctint=int64_t`). I also traced the coefficient buffer sizing, `top[-1]` access patterns, stack arrays in all motion-compensation and prediction functions, and the loop-filter bounds.

Key verification results:

- **`do_8tap_2d_c`**: `tmp[64*71]`, `tmp_h = h+7`, max h=64 → tmp_h=71. Fits exactly.
- **`do_scaled_8tap_c`**: `tmp[64*135]`, `tmp_h = (((h-1)*dy+my)>>4)+8`. With VP9 limits (h≤64, dy≤32, my≤15) → max tmp_h=134. Fits.
- **`do_scaled_bilin_c`**: `tmp[64*129]`, `tmp_h = (((h-1)*dy+my)>>4)+2`. Max tmp_h=128. Fits.
- **`itxfm_wrapper`**: block cast from `int16_t*` to `dctcoef*` (`int32_t` for 10bpp). Allocation at call site uses `bytesperpixel*sizeof(int16_t)` per coefficient = 4 bytes = `sizeof(int32_t)`. Correctly sized.
- **`top[-1]` accesses** in tm_*, diag_downright_*, vert_right_*, hor_down_*: intentional VP9 design; top-left reference sample at `top[-1]` is guaranteed by the decoder's reference sample setup.
- **Intra prediction macros** (diag_downleft, vert_left, hor_up, hor_down): all array bounds verified — varray sizes and memcpy lengths are within allocated stack arrays.
- **Loop filter**: accesses ±8 pixels/rows around filter edge — relies on standard VP9 frame padding, not attacker-controlled.
- **No `malloc`/`av_malloc` calls** anywhere in this file; no integer overflow leading to underallocation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

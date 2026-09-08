**Group 1 analysis (mss1.c lines 1–139):**

- `decode_pal`: `pal = ctx->pal + 256 - free_colours`; `ncol = arith_get_number(acoder, free_colours+1)` returns [0, free_colours]; last write at `ctx->pal + 255`. Bounded, no OOB.
- Arithmetic functions (`arith_get_bits`, `arith_get_number`, `arith_get_prob`): After normalization, `c->high <= 0xFFFF`, so products stay within `int`. `arith_get_prob` loop bounded by `cum_prob[num_syms] = 0 ≤ val` (val always ≥ 0).

**Group 2 analysis (mss1.c lines 141–229, mss12.c):**

- `mss1_decode_frame`: `pal_pic` / `pal_stride` set correctly for Y-flip; all accesses into `ff_mss12_decode_rect` stay within image bounds via validated `width`/`height`.
- `ff_mss12_decode_init`: `free_colours` validated by `(unsigned)c->free_colours > 256`; `coded_width`/`coded_height` clamped to [1, 4096]; `mask` allocated via `av_malloc_array(mask_stride, height)` where both dimensions ≤ 4096; extradata size checked before all field reads.
- `decode_pixel` / `decode_pixel_in_context`: `val = FFMIN(i, cache_size-1)` prevents OOB; `src[-1]` only accessed when `i > 0` (first pixel handled separately via `decode_pixel`); `src[-stride]` only accessed when `y > 0` i.e. a previously written row exists.
- `decode_pivot`: Returns -1 when `(unsigned)val >= base`; recursion depth bounded by `width + height ≤ 8192` — well within stack limits.
- `ff_mss12_model_update`: Inner backward scan bounded by `weights[0] = 0 ≠ weights[val] ≥ 1`; never goes below index 0.
- `idx2sym[idx]` returns `uint8_t` ∈ [0,255]; used as palette index into `c->pal[256]` — always valid.

After exhaustive analysis of all allocation sites, index calculations, arithmetic coder arithmetic, recursion depth, and data-flow from the untrusted bitstream through every memory-touching operation in `mss1.c` and its complete `mss12.c` dependency, no exploitable memory-safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

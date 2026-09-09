After thoroughly reading all 371 lines of `simple_idct_template.c` in three batches, plus its include context (`bit_depth_template.c`), the calling sites in `simple_idct.c`, `proresdsp.c`, `mpeg4videodec.c`, `idctdsp.c`, and the function pointer declaration in `idctdsp.h`, I have the complete picture.

**Key findings from analysis:**

1. **All array accesses are fixed-size**: Every access is to a hard-coded 8×8 IDCT block — `row[0..7]` and `col[0], col[8], ..., col[56]`. No attacker-controlled length drives these offsets.

2. **The `IN_IDCT_DEPTH == 32` type-pun is intentional and safe**: `ff_simple_idct_put_int32_10bit` casts `int16_t *block_` to `int32_t *`, but its callers in `mpeg4videodec.c` pass `(int16_t*)ctx->block32[i]` where `block32` is declared as `DECLARE_ALIGNED(8, int32_t, block32)[12][64]` — a proper 256-byte int32 buffer, not a 128-byte int16 buffer. The cast round-trip preserves a correctly-sized allocation.

3. **No dynamic memory allocation**: The template has no `malloc`, `av_malloc`, `av_realloc`, or `memcpy` of externally-controlled length.

4. **Arithmetic operations are protected against UB**: Intermediate values use `SUINT` (unsigned int) to avoid signed overflow UB. Final shifts produce values within the pixel type's range and are clamped by `av_clip_pixel`.

5. **`dest` pointer advances via `line_size`**: This comes from the frame allocator (not directly from the file) and represents the actual stride of the allocated frame buffer.

6. **`prores_idct_10`: `block[i] *= qmat[i]` on `int16_t`** — integer promotion means the multiplication is done in `int`, then truncated back to `int16_t`. Potential arithmetic error but no heap corruption (no index goes out of bounds).

7. **`lin_curve[seg]` in `put_pixel_bayer_lin_curve_12`**: `seg = av_clip_uint16(...) >> 13` yields at most 7; the guard `seg < 7` prevents `lin_curve[8]` access. No OOB.

No externally-triggerable memory safety vulnerability exists in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

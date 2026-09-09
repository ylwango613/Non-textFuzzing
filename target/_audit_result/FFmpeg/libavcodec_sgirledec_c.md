After reading the complete file (143 lines) and verifying all boundary conditions:

**Analysis summary:**

- **`decode_sgirle8()`**: All destination writes are doubly bounded: `length = FFMIN(v, width-x)` prevents row overflow, and `INC_XY(length)` explicitly `return 0`s from the function when `y >= height`. Source reads are bounded by `src_end` via the outer loop condition and `FFMIN3(..., src_end - src)`.
- **`sgirle_decode_frame()`**: The heuristic check at line 118 uses `avctx->width * avctx->height` (int × int) which can overflow for huge dimensions, but `ff_get_buffer()` independently validates dimensions and would fail before any decode. No allocation is done in the decoder itself.
- No `av_malloc`/`memcpy` with untrusted size, no fixed-size stack buffers, no chunk-size-to-malloc pattern.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

After thorough analysis—reading the full 456-line file, tracing all `ref[]` pointer arithmetic, verifying every write-then-check pattern, examining the `av_malloc_array` size computation, and cross-referencing the tiff.c caller path through `ff_set_dimensions` / `av_image_check_size2`—here is my assessment:

**Key areas checked:**

1. **`ref[2] = 0` when `avctx->width == 0` (runsize == 2)**: A real code-level OOB write of value 0. However, `av_image_check_size2` explicitly rejects `w == 0` with `AVERROR(EINVAL)`, and `ff_thread_get_buffer` / `av_frame_get_buffer` blocks the path before `ff_ccitt_unpack` is ever called with width=0. Not reachable in practice.

2. **"Write then check" pattern** (`*runs++ = X; if (runs >= runend) { error; }`): Appears in `decode_group3_1d_line`, `decode_group3_2d_line`, and `decode_uncompressed`. However, flow control guarantees that the write pointer can reach `runend` only on the write that stores the very last valid slot—the subsequent check then fires. The OOB slot is never actually written.

3. **`ref` pointer underflow in `decode_group3_2d_line`** (`*--ref` going below `ref_start[0]`): The no-sync-after-vertical-mode condition requires `ref[0] + delta < 0` (equivalently `run < 0` as unsigned → UINT_MAX), which is caught by the `run > width` check on line 334 before any OOB dereference occurs. Proven infeasible for all valid delta values (cmode ∈ {2..7}).

4. **Sync loop OOB read** (lines 347–350): Valid reference lines always have runs summing to `width`, guaranteeing `run_off` accumulates to exceed `offs < width` before exhausting the array.

5. **Integer overflow in `runsize = avctx->width + 2`**: Overflow produces a negative `int`, interpreted as a huge `size_t` by `av_malloc_array`, which fails and is caught by the `if (!runs || !ref)` NULL check.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

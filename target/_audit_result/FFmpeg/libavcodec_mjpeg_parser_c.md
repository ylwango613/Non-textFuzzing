I have now read the complete `mjpeg_parser.c` (137 lines) and all relevant helpers. My analysis covers:

**`find_frame_end()` state machine (lines 41–103):**
- `m->size = (state&0xFFFF) - 1`: when `state&0xFFFF == 0`, the `uint32_t` arithmetic wraps to UINT32_MAX, truncates to `int` → `-1`. Immediately guarded by `if(m->size > 0)` at lines 62/90, so the negative value is never used as a skip count. No bug.
- `FFMIN(buf_size-i, m->size)`: Both operands are non-negative (guarded by `m->size > 0` and loop invariant `i < buf_size`). Skip is bounded. No bug.
- Return `i-3` (line 83): Can be negative (e.g., when the SOI marker straddles buffer boundaries). `ff_combine_frame` handles negative-but-not-END_NOT_FOUND via the overread loop (lines 284–288 of parser.c). The state machine invariant guarantees `pc->index ≥ |next|` in these cases, so `pc->buffer[pc->last_index + next]` is always in-bounds. No bug.
- No memory allocations inside this file at all.

**`jpeg_parse()` (lines 105–129):** Pure delegation; no independent memory safety issues.

**`ff_combine_frame()` in parser.c:** The `av_fast_realloc` size expressions (`*buf_size + pc->index + AV_INPUT_BUFFER_PADDING_SIZE`) could theoretically overflow, but this is a generic parser utility not specific to `mjpeg_parser.c`, and in practice both values are bounded by reasonable packet sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

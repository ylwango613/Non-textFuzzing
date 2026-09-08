After thorough analysis of `latm_parser.c` (114 lines, fully read) and the `ff_combine_frame` implementation in `parser.c`:

**Key observations:**

1. **`latm_find_frame_end` arithmetic** (lines 55–80): `state` is `uint32_t`; `s->count` is `int`. The expression `(state & LATM_SIZE_MASK) - s->count` uses C's usual arithmetic conversions (`int` → `uint32_t`). When `s->count` is negative (early calls), the unsigned wrap-around produces a value larger than any valid `buf_size`, so the condition correctly evaluates to false. When `s->count` is positive and less than the 13-bit size field (max 8191), the subtraction is clean. The return path is only reachable when the result ≤ `buf_size`, guaranteeing the returned `int` is non-negative and ≤ INT_MAX.

2. **`ff_combine_frame` bounds** (parser.c lines 227–297): Guards `next > *buf_size` before any copy; `av_fast_realloc` sizes include `AV_INPUT_BUFFER_PADDING_SIZE`; `memcpy` lengths are bounded by `next + padding` ≤ `*buf_size + padding`, which is always within the padded allocation callers provide.

3. **`s->count` overflow**: theoretical UB if no complete frame arrives over millions of calls, but does not cause memory corruption—the condition at line 70 remains false after overflow.

4. **`latm_parse`**: No direct memory operations; delegates entirely to `latm_find_frame_end` + `ff_combine_frame`.

No exploitable memory-safety vulnerability was identified in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

I've now read the complete `gsm_parser.c` (93 lines), its header `gsm.h`, the `ff_combine_frame` implementation in `parser.c`, and the decoder `gsmdec.c` for cross-validation.

**Analysis summary:**

- `gsm_parse()` sets `s->block_size` to either the constant `GSM_BLOCK_SIZE`/`GSM_MS_BLOCK_SIZE` or `avctx->block_align` for GSM_MS. No bounds check on `block_align` in the parser.
- The decoder (`gsmdec.c:57-63`) **does** validate `block_align` (must be in `[MSN_MIN_BLOCK_SIZE, GSM_MS_BLOCK_SIZE]` and satisfy a modulo-3 constraint), returning `AVERROR_INVALIDDATA` on failure. By the time the parser operates on a fully-open codec context, `block_align` has already been sanitised.
- For negative `block_align`: `next` would become negative (not `END_NOT_FOUND=-100`). Inside `ff_combine_frame`, `av_assert0(next >= 0 || pc->buffer)` guards the path where `pc->buffer` could be NULL; with buffered data the subsequent `pc->buffer[pc->last_index + next]` stays within allocated bounds for small negative offsets. No heap underallocation or OOB write results.
- For very large `block_align`: causes incremental accumulation inside `ParseContext`, bounded by the operating system rejecting allocation. No integer overflow path to exploitable underallocation.
- No `av_malloc`/`memcpy` calls with attacker-controlled sizes that bypass size validation exist in this file; all allocations go through `av_fast_realloc` inside `ff_combine_frame` with properly guarded sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

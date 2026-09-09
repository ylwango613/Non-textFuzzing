Complete audit summary:

**`sipr_parser.c` (76 lines) — full trace:**

- `sipr_split()`: uses `avctx->block_align` (int) and `avctx->bit_rate` (int64_t) from the codec context. Both are attacker-controlled, but the entire function body only ever produces one of {19, 20, 29, 37}, then caps that with `FFMIN(next, buf_size)`. Result is always in `[0, 37]`.

- `sipr_parse()`: passes that bounded value to `ff_combine_frame`. No malloc, memcpy, or array indexing here at all.

- `ff_combine_frame()` (parser.c:213–298): For `next ∈ [0,37]` (the only values sipr can supply):
  - The guard `if (next > *buf_size) return AVERROR(EINVAL)` is satisfied since `next ≤ buf_size` by construction.
  - The `END_NOT_FOUND` (-100) accumulation branch is never taken.
  - The realloc size is `next + pc->index + AV_INPUT_BUFFER_PADDING_SIZE` — with `next ≤ 37` there is no integer overflow risk.
  - The `memcpy` into the reallocated buffer writes exactly `next + AV_INPUT_BUFFER_PADDING_SIZE` bytes at offset `pc->index`; the allocation is exactly that size past that offset.
  - The negative-`next` overread loop (lines 279–288) is unreachable because `next ≥ 0` always.

No heap allocations, no stack buffers, no unsafe casts, no unbounded arithmetic, and no attacker-reachable OOB path are present in `sipr_parser.c` or in the portion of `parser.c` it exercises.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

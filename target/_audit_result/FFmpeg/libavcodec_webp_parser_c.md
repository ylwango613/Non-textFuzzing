I've now fully analyzed `webp_parser.c` (114 lines) and its entire dependency chain:

- `ctx->fsize` is bounded by the explicit check `ctx->fsize > 15 && ctx->fsize <= UINT32_MAX - 10` before the `+= 8`, so `fsize` maxes at `UINT32_MAX - 2` — no integer overflow.
- `ctx->remaining_size = ctx->fsize + i - 15` in uint32_t arithmetic: since `ctx->fsize >= 24` and `i >= 0`, there is no underflow; overflow would require `i` near `UINT32_MAX` which the parser framework does not allow.
- `FFMIN(ctx->remaining_size, buf_size)` is a mixed uint32_t/int comparison — safe as long as `buf_size` is non-negative (guaranteed by the parser framework).
- The parser performs no heap allocation proportional to an attacker-controlled size; it delegates all buffer management to the generic `ff_combine_frame` / `av_fast_realloc` path, whose sizing is controlled by the actual bytes received, not a file-declared size.
- No stack buffers, no `memcpy` with attacker-controlled length, no extradata handling.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

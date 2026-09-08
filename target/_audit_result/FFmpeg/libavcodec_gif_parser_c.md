After a thorough audit of `gif_parser.c` and all referenced code:

- `gif_find_frame_end`: pure byte-by-byte state machine, all `buf[index]` accesses bounded by the `for (index = 0; index < buf_size; index++)` loop. No dynamic allocation.
- `gct_size`: `3 * (1 << ((buf[index] & 0x07) + 1))` → max 768, no integer overflow.
- `block_size`: read as a single `uint8_t` (0–255), used only as a loop counter, no memory allocation tied to it.
- `delay` shift: `buf[index] << (8 * (g->index - 1))`, max shift is 8 on a uint8_t (max 65280), fits in `int`.
- `ff_combine_frame`: uses `av_fast_realloc` with proper size arithmetic; the common parser infrastructure, not GIF-specific.
- Logic issues found (e.g., `g->index` not reset on some state transitions, dead `g->state != GIF_EXTENSION_BLOCK` check inside `!g->state` branch) are parsing accuracy bugs with no memory-corruption consequence.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->

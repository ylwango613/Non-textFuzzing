After full analysis of all data paths in `lscrdec.c`:

- **Buffer allocations** (`av_fast_padded_malloc` for `buffer`/`last_row`) are sized exactly to `w * 3 + 16` / `w * 3`, and `crow_buf = buffer + 15` with `crow_size = w*3+1` fills the allocation precisely.
- **Frame writes** via `ff_png_filter_row` are bounded: `x+w ≤ avctx->width` and `y+h ≤ avctx->height` checks on lines 152–154 prevent OOB row access; the `if (s->y < s->cur_h)` guard in `decode_idat` further limits calls to `handle_row`.
- **Bytestream reads** are all bounded by `bytestream2_*` functions that internally clamp via `av_clip` / `FFMIN`.
- **Type mismatches** (`int left` vs `uint32_t size/csize`): large `csize` is truncated to a negative `int length` in `decode_idat`, caught immediately by `if (length <= 0) return AVERROR_INVALIDDATA;`. Large `size` makes `left` negative, so the `while (left > 16)` loop never executes. `offset` integer overflow causes wrong seeks, but `bytestream2_seek` clamps via `av_clip`.
- **zlib input** is bounded: `avail_in = FFMIN(length, bytestream2_get_bytes_left(&s->gb))` ensures inflate never reads beyond the packet.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
